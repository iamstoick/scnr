// Package trivy drives the trivy binary over a local directory or a local
// image archive and parses its JSON report as hostile input. Vulnerability
// results use the shared sca.osv.<id>@<purl> scheme so they dedupe with the
// native engines and grype. trivy fetches its vulnerability and misconfig
// databases from ghcr.io; that download is allowed only when the scan is
// online (the same opt-in as OSV) and suppressed with the skip flags
// otherwise. Dependency resolution over the network (Maven central for
// pom.xml parents and properties, Terraform module downloads) is disabled
// in every mode: a scanned repository must never choose the endpoints an
// adapter contacts. Telemetry, version checks and client/server mode are
// off.
package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/engine/image"
	"github.com/iamstoick/scnr/internal/safety"
)

// Name of the engine.
const Name = "adapter:trivy"

// MinVersion we have fixtures for (--disable-telemetry exists from 0.58).
const MinVersion = "0.58.0"

const outputFile = "trivy.json"

var misconfIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// Adapter implements adapter.Adapter; Supports, Binary, Version and Detect
// come from the embedded SCABase.
type Adapter struct {
	adapter.SCABase
}

// New builds the adapter, borrowing SCA prose from the sca engine.
func New() (*Adapter, error) {
	b, err := adapter.NewSCABase("trivy", MinVersion, outputFile)
	if err != nil {
		return nil, err
	}
	return &Adapter{SCABase: b}, nil
}

// Name implements engine.Engine.
func (a *Adapter) Name() string { return Name }

// Plan implements engine.Engine.
func (a *Adapter) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	net := "offline: no DB download (--skip-db-update)"
	if o.Online {
		net = "may download its vulnerability/check DB from ghcr.io; never resolves dependencies or modules over the network (--offline-scan)"
	}
	return a.PlanTool(ctx, a, t, o, "vuln,misconfig,secret scanners; "+net, 10*time.Minute)
}

// Args builds the argument array (Section 5.6).
func (a *Adapter) Args(t domain.Target, o engine.Options) ([]string, error) {
	if t.Type == domain.TargetImage && !image.IsLocal(t) {
		return nil, image.SkipRegistry(t) // never a pull through trivy's own network stack
	}
	if err := adapter.FlagSafePath(t.Value); err != nil {
		return nil, err
	}
	var args []string
	switch t.Type {
	case domain.TargetPath:
		args = []string{"fs"}
	case domain.TargetImage:
		args = []string{"image", "--input", t.Value}
	default:
		return nil, fmt.Errorf("trivy: unsupported target type %s", t.Type)
	}
	args = append(args,
		"--format", "json", "--output", a.OutputPath(o),
		"--scanners", "vuln,misconfig,secret",
		"--quiet", "--no-progress",
		"--disable-telemetry",  // no usage reporting
		"--skip-version-check", // no release check
		"--timeout", "15m",
		// Always: no API requests to resolve dependencies (Maven central for
		// pom.xml parents/properties and the like). The scanned tree decides
		// what trivy parses; it must not decide where trivy connects.
		"--offline-scan",
		// Always: Terraform modules trivy downloaded on its own are excluded
		// from results. Whether a current trivy still fetches remote modules
		// when scanning with --offline-scan is not verified against a live
		// binary (SAFETY.md item 10).
		"--tf-exclude-downloaded-modules",
	)
	if !o.Online {
		args = append(args, "--skip-db-update", "--skip-java-db-update", "--skip-check-update")
	}
	if t.Type == domain.TargetPath {
		args = append(args, "--", t.Value)
	}
	return args, nil
}

// Run implements engine.Engine.
func (a *Adapter) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	return a.RunSCA(ctx, a, t, o, emit)
}

// Field allowlists for the trivy JSON schema (v2).
type result struct {
	Target            string    `json:"Target"`
	Class             string    `json:"Class"`
	Type              string    `json:"Type"`
	Vulnerabilities   []vuln    `json:"Vulnerabilities"`
	Misconfigurations []misconf `json:"Misconfigurations"`
	Secrets           []secret  `json:"Secrets"`
}

type vuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CweIDs           []string `json:"CweIDs"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	CVSS map[string]struct {
		V3Vector string  `json:"V3Vector"`
		V3Score  float64 `json:"V3Score"`
	} `json:"CVSS"`
}

type misconf struct {
	Type          string   `json:"Type"`
	ID            string   `json:"ID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	PrimaryURL    string   `json:"PrimaryURL"`
	References    []string `json:"References"`
	CauseMetadata struct {
		StartLine int `json:"StartLine"`
	} `json:"CauseMetadata"`
}

type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	Match     string `json:"Match"`
}

// osDBPath maps trivy's OS type to the database path native engines and
// grype report, so OS package findings share a location.
func osDBPath(typ string) string {
	switch strings.ToLower(typ) {
	case "alpine":
		return "lib/apk/db/installed"
	case "debian", "ubuntu":
		return "var/lib/dpkg/status"
	case "redhat", "centos", "rocky", "alma", "fedora", "amazon", "oracle", "suse", "opensuse", "photon":
		return "var/lib/rpm/Packages"
	}
	return "os:" + strings.ToLower(typ)
}

// osEcosystem maps trivy OS type to the OSV ecosystem used when no PURL is
// present (older trivy versions).
func osEcosystem(typ string) string {
	switch strings.ToLower(typ) {
	case "alpine":
		return "Alpine"
	case "debian":
		return "Debian"
	case "ubuntu":
		return "Ubuntu"
	}
	return ""
}

// langEcosystem maps trivy language types to OSV ecosystems.
var langEcosystem = map[string]string{
	"npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm",
	"pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "python-pkg": "PyPI",
	"gomod": "Go", "gobinary": "Go", "bundler": "RubyGems", "gemspec": "RubyGems",
	"cargo": "crates.io", "composer": "Packagist", "pom": "Maven", "gradle": "Maven", "jar": "Maven",
}

// Parse reads Results[] from the JSON report.
func (a *Adapter) Parse(r io.Reader, emit func(domain.Finding) error) error {
	red := safety.NewRedactor()
	bad, err := adapter.StreamArray(r, "Results", func(dec *json.Decoder) error {
		var res result
		if err := adapter.DecodeElement(dec, &res); err != nil {
			return err
		}
		return a.results(&res, red, emit)
	})
	if err != nil {
		return fmt.Errorf("trivy output: %w", err)
	}
	return adapter.BadCount("trivy", bad)
}

func (a *Adapter) results(res *result, red *safety.Redactor, emit func(domain.Finding) error) error {
	loc, ok := a.location(res)
	if !ok {
		return adapter.ErrSkipElement
	}
	eco := langEcosystem[strings.ToLower(res.Type)]
	if res.Class == "os-pkgs" {
		eco = osEcosystem(res.Type)
	}
	for i := range res.Vulnerabilities {
		v := &res.Vulnerabilities[i]
		rec := adapter.Vuln{
			ID: v.VulnerabilityID, PURL: v.PkgIdentifier.PURL, Ecosystem: eco, Name: v.PkgName, Version: v.InstalledVersion, Fixed: v.FixedVersion,
			Severity: v.Severity, Title: v.Title, Description: v.Description, Location: loc,
		}
		if v.PrimaryURL != "" {
			rec.References = append(rec.References, v.PrimaryURL)
		}
		rec.References = append(rec.References, v.References...)
		if len(v.CweIDs) > 0 {
			rec.CWE = v.CweIDs[0]
		}
		for _, src := range []string{"nvd", "ghsa", "redhat", "bitnami"} {
			if c, ok := v.CVSS[src]; ok && c.V3Vector != "" {
				rec.CVSSVector, rec.CVSSScore = c.V3Vector, c.V3Score
				break
			}
		}
		f, ok := rec.Finding(a.Rules, red, a.AssetKey, "trivy")
		if !ok {
			continue
		}
		if err := emit(f); err != nil {
			return err
		}
	}
	for i := range res.Misconfigurations {
		if f, ok := a.misconfFinding(&res.Misconfigurations[i], loc, red); ok {
			if err := emit(f); err != nil {
				return err
			}
		}
	}
	for i := range res.Secrets {
		if f, ok := a.secretFinding(&res.Secrets[i], loc, red); ok {
			if err := emit(f); err != nil {
				return err
			}
		}
	}
	return nil
}

// location derives the repo-relative or OS-db location of a result.
func (a *Adapter) location(res *result) (string, bool) {
	if res.Class == "os-pkgs" {
		return osDBPath(res.Type), true
	}
	target := res.Target
	if i := strings.Index(target, " ("); i > 0 && res.Class == "" { // "image:tag (alpine 3.18)" without class
		target = target[:i]
	}
	return adapter.RelLocation(a.Root, target)
}

func (a *Adapter) misconfFinding(m *misconf, loc string, red *safety.Redactor) (domain.Finding, bool) {
	if !misconfIDRe.MatchString(m.ID) {
		return domain.Finding{}, false
	}
	sev, ok := adapter.Severity(m.Severity)
	if !ok {
		return domain.Finding{}, false
	}
	if m.CauseMetadata.StartLine > 0 {
		loc += ":" + strconv.Itoa(m.CauseMetadata.StartLine)
	}
	f := domain.Finding{AssetKey: a.AssetKey, RuleID: "trivy:" + m.ID, Engine: Name, Severity: sev, Confidence: domain.Firm, Location: loc, Status: domain.StatusOpen}
	f.Title = red.Clean(m.Title, 200)
	if f.Title == "" {
		f.Title = "trivy misconfiguration " + m.ID
	}
	f.WhatItIs = red.Clean(m.Description, 2000)
	if f.WhatItIs == "" {
		f.WhatItIs = "trivy check " + m.ID + " failed (no description from trivy)."
	} else {
		f.WhatItIs += " (description from trivy)"
	}
	f.WhyItMatters = "This infrastructure-as-code check comes from trivy's policy bundle; its severity is trivy's own assessment."
	f.HowToFix = red.Clean(m.Resolution, 2000)
	if f.HowToFix == "" {
		f.HowToFix = "Follow the referenced policy documentation and change the configuration accordingly."
	}
	f.CVEs = []string{}
	f.References = adapter.URLRefs(append([]string{m.PrimaryURL}, m.References...)...)
	f.Fingerprint = domain.Fingerprint(f.RuleID, a.AssetKey, loc)
	f.Evidence = []domain.Evidence{red.TextEvidence("file", loc, red.Clean(m.Message, domain.MaxEvidenceBytes))}
	return f, true
}

// secretFinding maps a trivy secret to `secret:<RuleID>`; the match text is
// redacted again by our redactor and the raw value is never kept.
func (a *Adapter) secretFinding(s *secret, loc string, red *safety.Redactor) (domain.Finding, bool) {
	if !misconfIDRe.MatchString(s.RuleID) {
		return domain.Finding{}, false
	}
	sev, ok := adapter.Severity(s.Severity)
	if !ok {
		return domain.Finding{}, false
	}
	if s.StartLine > 0 {
		loc += ":" + strconv.Itoa(s.StartLine)
	}
	f := domain.Finding{AssetKey: a.AssetKey, RuleID: "secret:" + s.RuleID, Engine: Name, Severity: sev, Confidence: domain.Firm, Location: loc, Status: domain.StatusOpen}
	f.Title = red.Clean(s.Title, 200)
	if f.Title == "" {
		f.Title = "trivy secret " + s.RuleID
	}
	f.WhatItIs = fmt.Sprintf("trivy's secret scanner matched rule %s (%s) at this location. (description from trivy)", s.RuleID, red.Clean(s.Category, 60))
	f.WhyItMatters = "A credential in a repository or image is readable by everyone with access to it and survives in history and layers after deletion."
	f.HowToFix = "Rotate the credential, remove it from the source or image, and load it at run time from a secret store."
	f.CVEs = []string{}
	f.References = []string{}
	f.CWE = "CWE-798"
	f.Fingerprint = domain.Fingerprint(f.RuleID, a.AssetKey, loc)
	// trivy already masks the value; redact again and keep only a hash of
	// its (masked) form so no raw fragment can leak through a format change.
	masked := red.Redact(safety.StripControl(s.Match))
	if len(masked) > 256 {
		masked = masked[:256]
	}
	f.Evidence = []domain.Evidence{{Kind: "file", Location: loc, Redacted: safety.Mask(masked), Hash: domain.SHA256Hex(masked)}}
	return f, true
}

var _ adapter.Adapter = (*Adapter)(nil)
