// Package plugin runs third-party checks as sandboxed out-of-process
// engines: signed manifests, a tamper-evident lock file, stdin/stdout
// JSONL over a capped pipe, and an optional HTTP broker for scoped
// network. Everything the child emits is treated as hostile input.
package plugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"

	"golang.org/x/mod/semver"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
)

// ProtocolVersion is the only plugin protocol this scnr speaks.
const ProtocolVersion = 1

// Size caps.
const (
	MaxManifestBytes  = 64 << 10
	MaxRules          = 200
	MaxTarballBytes   = 64 << 10 << 10
	MaxTarEntries     = 64
	MaxSignatureBytes = 4 << 10
)

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)
	versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// Manifest is the validated plugin.json content. BinarySHA256 pins the
// payload the signature transitively covers.
type Manifest struct {
	Protocol     int                  `json:"protocol"`
	Name         string               `json:"name"`
	Version      string               `json:"version"`
	Description  string               `json:"description"`
	Homepage     string               `json:"homepage"`
	Supports     []string             `json:"supports"`
	Safety       string               `json:"safety"`
	Capabilities ManifestCapabilities `json:"capabilities"`
	BinarySHA256 string               `json:"binary_sha256"`
	Rules        []ManifestRule       `json:"rules"`
}

// ManifestCapabilities is the manifest's capability declaration.
type ManifestCapabilities struct {
	Network    string `json:"network"`
	Filesystem string `json:"filesystem"`
}

// ManifestRule is one check the plugin may emit. The installed rule id is
// "plugin.<name>.<id>" with engine "plugin:<name>".
type ManifestRule struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	What       string   `json:"what"`
	Why        string   `json:"why"`
	Fix        string   `json:"fix"`
	CWE        string   `json:"cwe,omitempty"`
	References []string `json:"references,omitempty"`
}

var validTargets = map[string]bool{"path": true, "url": true, "host": true, "image": true}

// ParseManifest strictly decodes and validates manifest bytes, returning
// the manifest and its installed rules (validated by engine.ValidateRule
// like every native rule).
func ParseManifest(b []byte) (*Manifest, []domain.Rule, error) {
	if len(b) == 0 || len(b) > MaxManifestBytes {
		return nil, nil, fmt.Errorf("manifest: %d bytes, want 1..%d", len(b), MaxManifestBytes)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Protocol != ProtocolVersion {
		return nil, nil, fmt.Errorf("manifest: protocol %d, want %d", m.Protocol, ProtocolVersion)
	}
	if !nameRe.MatchString(m.Name) {
		return nil, nil, fmt.Errorf("manifest: bad name %q", m.Name)
	}
	if !versionRe.MatchString(m.Version) || !semver.IsValid("v"+m.Version) {
		return nil, nil, fmt.Errorf("manifest: version %q is not strict semver", m.Version)
	}
	if m.Description == "" || len(m.Description) > 2048 {
		return nil, nil, fmt.Errorf("manifest: description must be 1..2048 chars")
	}
	if m.Homepage != "" {
		u, err := url.Parse(m.Homepage)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || len(m.Homepage) > 512 {
			return nil, nil, fmt.Errorf("manifest: bad homepage %q", m.Homepage)
		}
	}
	if len(m.Supports) == 0 || len(m.Supports) > 4 {
		return nil, nil, fmt.Errorf("manifest: supports must list 1..4 target types")
	}
	seen := map[string]bool{}
	for _, s := range m.Supports {
		if !validTargets[s] || seen[s] {
			return nil, nil, fmt.Errorf("manifest: bad supports entry %q", s)
		}
		seen[s] = true
	}
	if m.Safety != "safe" {
		return nil, nil, fmt.Errorf("manifest: safety %q, only \"safe\" plugins exist in 4e", m.Safety)
	}
	if m.Capabilities.Network != "none" && m.Capabilities.Network != "broker" {
		return nil, nil, fmt.Errorf("manifest: network %q, want none|broker", m.Capabilities.Network)
	}
	if m.Capabilities.Filesystem != "target-readonly" {
		return nil, nil, fmt.Errorf("manifest: filesystem %q, want target-readonly", m.Capabilities.Filesystem)
	}
	hash, err := hex.DecodeString(m.BinarySHA256)
	if err != nil || len(hash) != 32 {
		return nil, nil, fmt.Errorf("manifest: binary_sha256 must be 64 hex chars")
	}
	if len(m.Rules) == 0 || len(m.Rules) > MaxRules {
		return nil, nil, fmt.Errorf("manifest: rules must list 1..%d entries", MaxRules)
	}
	engineName := "plugin:" + m.Name
	rules := make([]domain.Rule, 0, len(m.Rules))
	for _, r := range m.Rules {
		dr := domain.Rule{
			ID: "plugin." + m.Name + "." + r.ID, Engine: engineName,
			Title: r.Title, Severity: r.Severity, CWE: r.CWE,
			WhatItIs: r.What, WhyItMatters: r.Why, HowToFix: r.Fix,
			References: adapter.URLRefs(r.References...), Safety: m.Safety,
			Tags: []string{"plugin", m.Name},
		}
		if err := engine.ValidateRule(dr, engineName); err != nil {
			return nil, nil, fmt.Errorf("manifest rule %q: %w", r.ID, err)
		}
		rules = append(rules, dr)
	}
	return &m, rules, nil
}

// BinaryName is the required payload file name for a manifest name.
func BinaryName(name string) string { return "scnr-plugin-" + name }

// CompareVersions orders strict semver (locked entries are valid by
// construction; invalid input sorts below everything).
func CompareVersions(a, b string) int {
	if !versionRe.MatchString(a) {
		return -1
	}
	if !versionRe.MatchString(b) {
		return 1
	}
	return semver.Compare("v"+a, "v"+b)
}

// fingerprint renders the audit/display form of a publisher key: the
// first 32 hex chars of SHA-256, same shape as the bundle keys.
func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:])[:32]
}
