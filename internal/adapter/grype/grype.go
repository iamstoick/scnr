// Package grype drives the grype binary over a local directory or local
// image archive and parses its JSON report as hostile input. Matches use the
// shared sca.osv.<id>@<purl> scheme so they dedupe with the native engines
// and trivy. grype refreshes its vulnerability DB from Anchore's CDN on
// every run by default; that is allowed only when the scan is online (same
// opt-in as OSV) and disabled via GRYPE_DB_AUTO_UPDATE=false otherwise.
// The application update check is always off.
package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/engine/image"
	"github.com/iamstoick/scnr/internal/safety"
)

// Name of the engine.
const Name = "adapter:grype"

// MinVersion we have fixtures for.
const MinVersion = "0.70.0"

const outputFile = "grype.json"

// Adapter implements adapter.Adapter; Supports, Binary, Version and Detect
// come from the embedded SCABase.
type Adapter struct {
	adapter.SCABase
}

// New builds the adapter, borrowing SCA prose from the sca engine.
func New() (*Adapter, error) {
	b, err := adapter.NewSCABase("grype", MinVersion, outputFile, "GRYPE_CHECK_FOR_APP_UPDATE=false")
	if err != nil {
		return nil, err
	}
	return &Adapter{SCABase: b}, nil
}

// Name implements engine.Engine.
func (a *Adapter) Name() string { return Name }

// Plan implements engine.Engine.
func (a *Adapter) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	net := "offline: no DB download (GRYPE_DB_AUTO_UPDATE=false)"
	if o.Online {
		net = "may refresh its vulnerability DB from Anchore"
	}
	return a.PlanTool(ctx, a, t, o, "package vulnerability matching; "+net, 10*time.Minute)
}

// source returns the grype source string for the target. Only local
// sources are ever named: a directory, a docker-archive or an OCI layout.
func source(t domain.Target) (string, error) {
	if t.Type == domain.TargetImage && !image.IsLocal(t) {
		return "", image.SkipRegistry(t) // never a pull through grype's own network stack
	}
	if err := adapter.FlagSafePath(t.Value); err != nil {
		return "", err
	}
	switch t.Type {
	case domain.TargetPath:
		return "dir:" + t.Value, nil
	case domain.TargetImage:
		if t.Labels[image.SourceLabel] == image.SourceOCILayout {
			return "oci-dir:" + t.Value, nil
		}
		return "docker-archive:" + t.Value, nil
	}
	return "", fmt.Errorf("grype: unsupported target type %s", t.Type)
}

// Args builds the argument array (Section 5.6). It also fixes the child
// environment for this run: DB auto-update only when online.
func (a *Adapter) Args(t domain.Target, o engine.Options) ([]string, error) {
	src, err := source(t)
	if err != nil {
		return nil, err
	}
	a.SetEnv = []string{"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_AUTO_UPDATE=" + map[bool]string{true: "true", false: "false"}[o.Online]}
	return []string{src, "-o", "json", "--file", a.OutputPath(o), "-q"}, nil
}

// Env returns the fixed child environment (for tests).
func (a *Adapter) Env() []string { return a.SetEnv }

// Run implements engine.Engine.
func (a *Adapter) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	return a.RunSCA(ctx, a, t, o, emit)
}

// match is the field allowlist for one matches[] element.
type match struct {
	Vulnerability struct {
		ID          string   `json:"id"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		DataSource  string   `json:"dataSource"`
		URLs        []string `json:"urls"`
		Fix         struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
		CVSS []cvss `json:"cvss"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		ID         string   `json:"id"`
		DataSource string   `json:"dataSource"`
		URLs       []string `json:"urls"`
		CVSS       []cvss   `json:"cvss"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"`
		PURL      string `json:"purl"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
		CPEs []string `json:"cpes"`
	} `json:"artifact"`
}

type cvss struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

// typeEcosystem maps grype artifact types to OSV ecosystems (used only when
// the PURL is missing or unparsable).
var typeEcosystem = map[string]string{
	"npm": "npm", "python": "PyPI", "go-module": "Go", "gem": "RubyGems", "rust-crate": "crates.io", "php-composer": "Packagist", "java-archive": "Maven",
	"apk": "Alpine", "deb": "Debian",
}

// Parse reads matches[] from the JSON report.
func (a *Adapter) Parse(r io.Reader, emit func(domain.Finding) error) error {
	red := safety.NewRedactor()
	bad, err := adapter.StreamArray(r, "matches", func(dec *json.Decoder) error {
		var m match
		if err := adapter.DecodeElement(dec, &m); err != nil {
			return err
		}
		f, ok := a.finding(&m, red)
		if !ok {
			return adapter.ErrSkipElement
		}
		return emit(f)
	})
	if err != nil {
		return fmt.Errorf("grype output: %w", err)
	}
	return adapter.BadCount("grype", bad)
}

func (a *Adapter) finding(m *match, red *safety.Redactor) (domain.Finding, bool) {
	loc := ""
	for _, l := range m.Artifact.Locations {
		if rel, ok := adapter.RelLocation(a.Root, l.Path); ok {
			loc = rel
			break
		}
	}
	if loc == "" {
		return domain.Finding{}, false
	}
	rec := adapter.Vuln{
		ID: m.Vulnerability.ID, PURL: m.Artifact.PURL, Ecosystem: typeEcosystem[strings.ToLower(m.Artifact.Type)],
		Name: m.Artifact.Name, Version: m.Artifact.Version, Severity: m.Vulnerability.Severity,
		Description: m.Vulnerability.Description, Location: loc,
	}
	if len(m.Vulnerability.Fix.Versions) > 0 && m.Vulnerability.Fix.State != "not-fixed" {
		rec.Fixed = m.Vulnerability.Fix.Versions[0]
	}
	rec.References = append([]string{m.Vulnerability.DataSource}, m.Vulnerability.URLs...)
	for _, rv := range m.RelatedVulnerabilities {
		rec.Aliases = append(rec.Aliases, rv.ID)
		rec.References = append(append(rec.References, rv.DataSource), rv.URLs...)
	}
	all := append([]cvss{}, m.Vulnerability.CVSS...)
	for _, rv := range m.RelatedVulnerabilities {
		all = append(all, rv.CVSS...)
	}
	for _, c := range all {
		if strings.HasPrefix(c.Version, "3") && strings.HasPrefix(c.Vector, "CVSS:3") {
			rec.CVSSVector, rec.CVSSScore = c.Vector, c.Metrics.BaseScore
			break
		}
	}
	return rec.Finding(a.Rules, red, a.AssetKey, "grype")
}

var _ adapter.Adapter = (*Adapter)(nil)
