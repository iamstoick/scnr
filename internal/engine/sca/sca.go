// Package sca parses lockfiles and looks installed versions up in OSV.
package sca

import (
	"context"
	"embed"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
)

//go:embed rules/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "sca"

// Engine implements engine.Engine.
type Engine struct {
	rules engine.RuleSet
	OSV   *OSVClient
}

// New loads rules; the OSV client is injected by the caller (it needs the
// store for caching).
func New(osv *OSVClient) (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	if osv == nil {
		osv = &OSVClient{}
	}
	return &Engine{rules: rs, OSV: osv}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Rules exposes the rule prose for adapters that emit shared-scheme SCA
// findings (trivy, grype).
func (e *Engine) Rules() engine.RuleSet { return e.rules }

// Supports path targets.
func (e *Engine) Supports(t domain.Target) bool { return t.Type == domain.TargetPath }

// Collect walks the tree and parses every supported lockfile.
func Collect(ctx context.Context, root string) ([]Package, []string, error) {
	var pkgs []Package
	var files []string
	_, err := engine.WalkFiles(ctx, root, func(rel string, content []byte) error {
		p, ok := ParserFor(path.Base(rel))
		if !ok {
			return nil
		}
		if len(content) > MaxLockfileBytes {
			return nil
		}
		got, err := p.Parse(rel, content)
		if err != nil {
			return nil // a malformed lockfile is skipped, not fatal
		}
		files = append(files, rel)
		pkgs = append(pkgs, got...)
		return nil
	})
	return pkgs, files, err
}

// Plan implements engine.Engine.
func (e *Engine) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	pkgs, files, err := Collect(ctx, t.Value)
	if err != nil {
		return engine.Plan{}, err
	}
	p := engine.Plan{Summary: fmt.Sprintf("%d packages from %d lockfile(s)", len(pkgs), len(files)), Network: o.Online}
	if o.Online {
		p.Summary += "; package names and versions will be sent to api.osv.dev"
		p.EstRequests = len(pkgs)/osvBatchSize + 1
		p.EstDuration = 10 * time.Second
	} else {
		p.Summary += "; offline: OSV lookup skipped"
	}
	return p, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	pkgs, _, err := Collect(ctx, t.Value)
	if err != nil {
		return err
	}
	if len(pkgs) == 0 {
		return nil
	}
	return e.Lookup(ctx, pkgs, t.AssetKey(), Name, o, emit)
}

// MaxLookupPackages caps how many packages one Lookup sends to OSV. A tree
// or image with many lockfiles can exceed any single file's cap; the excess
// is dropped and reported as sca.lookup-truncated, never silently.
const MaxLookupPackages = 200_000

// RuleLookupTruncated is emitted when Lookup dropped packages past the cap.
const RuleLookupTruncated = "sca.lookup-truncated"

// Lookup queries OSV for pkgs and emits one finding per (vulnerability,
// package) under the shared sca.osv.<id>@<purl> scheme. label names the
// engine in the evidence text so a finding reached by several engines
// (native, image, trivy, grype) lists each of them. Offline yields a
// SkipError so the caller's scan is marked partial, not failed.
func (e *Engine) Lookup(ctx context.Context, pkgs []Package, assetKey, label string, o engine.Options, emit engine.EmitFunc) error {
	if len(pkgs) == 0 {
		return nil
	}
	if !o.Online {
		return &engine.SkipError{Reason: "offline"}
	}
	if len(pkgs) > MaxLookupPackages {
		f := e.rules.NewFinding(RuleLookupTruncated, assetKey, label, domain.Confirmed)
		f.Evidence = []domain.Evidence{{Kind: "file", Location: label, Redacted: fmt.Sprintf("%s: %d packages found; only the first %d were looked up (%d not checked)", label, len(pkgs), MaxLookupPackages, len(pkgs)-MaxLookupPackages), Hash: domain.SHA256Hex(label)}}
		if err := emit(f); err != nil {
			return err
		}
		pkgs = pkgs[:MaxLookupPackages]
	}
	ids, err := e.OSV.QueryBatch(ctx, pkgs)
	if err != nil {
		return err
	}
	uniq := map[string]bool{}
	var all []string
	for _, l := range ids {
		for _, id := range l {
			if !uniq[id] {
				uniq[id] = true
				all = append(all, id)
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	vulns, err := e.OSV.GetVulns(ctx, all)
	if err != nil {
		return err
	}
	for i, p := range pkgs {
		for _, id := range ids[i] {
			v := vulns[id]
			if v == nil {
				continue
			}
			if err := emit(e.finding(assetKey, label, p, v)); err != nil {
				return err
			}
		}
	}
	return nil
}

var cvssV3Re = regexp.MustCompile(`^CVSS:3\.[01]/`)

// VulnRuleID returns the shared rule ID for a vulnerability in a package:
// the CVE alias when one exists (so every tool agrees), else the source ID.
func VulnRuleID(id string, aliases []string, purl string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			id = a
			break
		}
	}
	return "sca.osv." + id + "@" + purl
}

func (e *Engine) finding(assetKey, label string, p Package, v *Vuln) domain.Finding {
	purl := p.PURL()
	loc := p.File
	if p.Line > 0 {
		loc += ":" + strconv.Itoa(p.Line)
	}
	f := domain.Finding{AssetKey: assetKey, Location: loc, Confidence: domain.Firm, Status: domain.StatusOpen}
	e.rules.MustGet("sca.vulnerable-dependency").Apply(&f)
	f.RuleID = VulnRuleID(v.ID, v.Aliases, purl)
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, loc)
	title := v.Summary
	if title == "" {
		title = v.ID
	}
	f.Title = fmt.Sprintf("%s %s: %s", p.Name, p.Version, title)
	f.WhatItIs = fmt.Sprintf("%s version %s (from %s) is affected by %s. %s", p.Name, p.Version, p.File, v.ID, firstSentence(v.Details))
	for _, a := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(a, "CVE-") {
			f.CVEs = append(f.CVEs, a)
		}
	}
	if f.CVEs == nil {
		f.CVEs = []string{}
	}
	if len(v.DatabaseSpecific.CWEIDs) > 0 {
		f.CWE = v.DatabaseSpecific.CWEIDs[0]
	}
	f.References = []string{"https://osv.dev/vulnerability/" + v.ID}
	for _, r := range v.References {
		if r.URL != "" && len(f.References) < 6 {
			f.References = append(f.References, r.URL)
		}
	}
	f.Severity, f.CVSS = severityFor(v)
	if fixed := fixedVersion(v, p); fixed != "" {
		f.HowToFix = fmt.Sprintf("Upgrade `%s` to `%s` or later.", p.Name, fixed)
	} else {
		f.HowToFix = fmt.Sprintf("No fixed version is published yet for `%s`. Check %s for mitigations and watch for a release.", p.Name, f.References[0])
	}
	f.Evidence = []domain.Evidence{PackageEvidence(label, loc, p.Ecosystem, p.Name, p.Version, purl)}
	return f
}

// PackageEvidence is the evidence row every SCA source attaches: which
// engine saw the package, in which ecosystem, at which version. The hash is
// of the PURL so re-scans confirm the same package without storing more.
func PackageEvidence(engineLabel, loc, ecosystem, name, version, purl string) domain.Evidence {
	return domain.Evidence{Kind: "file", Location: loc, Redacted: fmt.Sprintf("%s: %s %s %s", engineLabel, ecosystem, name, version), Hash: domain.SHA256Hex(purl)}
}

func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 && i < 300 {
		return s[:i+1]
	}
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// severityFor derives Severity from CVSS v3 in severity[], else
// database_specific.severity, else Medium.
func severityFor(v *Vuln) (domain.Severity, *domain.CVSS) {
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") && cvssV3Re.MatchString(s.Score) {
			score := cvssV3BaseScore(s.Score)
			if score > 0 {
				return severityFromScore(score), &domain.CVSS{Vector: s.Score, Score: score}
			}
		}
	}
	label := v.DatabaseSpecific.Severity
	if label == "" {
		for _, a := range v.Affected {
			if a.DatabaseSpecific.Severity != "" {
				label = a.DatabaseSpecific.Severity
				break
			}
			if a.EcosystemSpecific.Severity != "" {
				label = a.EcosystemSpecific.Severity
				break
			}
		}
	}
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return domain.Critical, nil
	case "HIGH":
		return domain.High, nil
	case "MODERATE", "MEDIUM":
		return domain.Medium, nil
	case "LOW":
		return domain.Low, nil
	}
	return domain.Medium, nil
}

func severityFromScore(s float64) domain.Severity {
	switch {
	case s >= 9.0:
		return domain.Critical
	case s >= 7.0:
		return domain.High
	case s >= 4.0:
		return domain.Medium
	case s > 0:
		return domain.Low
	}
	return domain.Info
}

// fixedVersion returns the first "fixed" event across ranges for the
// package; it prefers the smallest fixed version greater than installed
// when versions are comparable, else the first listed.
func fixedVersion(v *Vuln, p Package) string {
	var fixes []string
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, p.Ecosystem) || !strings.EqualFold(a.Package.Name, p.QueryName()) {
			continue
		}
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					fixes = append(fixes, ev.Fixed)
				}
			}
		}
	}
	if len(fixes) == 0 {
		return ""
	}
	sort.SliceStable(fixes, func(i, j int) bool { return compareVersions(fixes[i], fixes[j]) < 0 })
	for _, f := range fixes {
		if compareVersions(f, p.Version) > 0 {
			return f
		}
	}
	return fixes[len(fixes)-1]
}

// compareVersions is a lenient dotted-numeric comparison (good enough for
// picking a fix to name; Phase 4 adds semver matching).
func compareVersions(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(leadingDigits(as[i]))
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(leadingDigits(bs[i]))
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}
