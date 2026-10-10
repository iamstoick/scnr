// Package semgrep drives the semgrep binary in read-only scan mode
// (--metrics=off, no autofix, OSS engine only) and parses its JSON report
// as hostile input. Rules come from a local path when scnr.yaml sets
// tools.semgrep_rules; otherwise, and only when the scan is online, the
// registry pack p/default is used, which semgrep fetches from semgrep.dev
// (the only network it does; metrics stay off). An offline scan without
// local rules skips the engine rather than fetching. `--config auto` is
// never used: it uploads project metadata.
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
)

// Name of the engine.
const Name = "adapter:semgrep"

// MinVersion we have fixtures for.
const MinVersion = "1.50.0"

// DefaultConfig is the registry ruleset used when no local rules are set.
const DefaultConfig = "p/default"

const outputFile = "semgrep.json"

var checkIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,199}$`)

// Adapter implements adapter.Adapter.
type Adapter struct {
	adapter.Base
	root string // scan root, for relative locations
}

// New builds the adapter.
func New() *Adapter {
	return &Adapter{Base: adapter.Base{BinaryName: "semgrep", Min: MinVersion}}
}

// Name implements engine.Engine.
func (a *Adapter) Name() string { return Name }

// Supports path targets.
func (a *Adapter) Supports(t domain.Target) bool { return t.Type == domain.TargetPath }

// skipOfflineNoRules is the reason semgrep is skipped on an offline scan
// without tools.semgrep_rules: the only alternative would fetch p/default.
const skipOfflineNoRules = "offline and tools.semgrep_rules is not set: semgrep would download the registry pack " + DefaultConfig + " from semgrep.dev; set tools.semgrep_rules in scnr.yaml to a local ruleset, or run without --offline"

// Plan implements engine.Engine.
func (a *Adapter) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	src := "rules fetched from the semgrep.dev registry pack " + DefaultConfig + " (set tools.semgrep_rules for a local ruleset)"
	switch {
	case o.SemgrepRules != "":
		src = "local rules " + o.SemgrepRules
	case !o.Online:
		src = "will be skipped: " + skipOfflineNoRules
	}
	return a.PlanTool(ctx, a, t, o, "SAST, read-only, metrics off, "+src, 5*time.Minute)
}

// Args builds the argument array (Section 5.5).
func (a *Adapter) Args(t domain.Target, o engine.Options) ([]string, error) {
	if err := adapter.FlagSafePath(t.Value); err != nil {
		return nil, err
	}
	cfg := DefaultConfig
	if o.SemgrepRules != "" {
		if err := adapter.FlagSafePath(o.SemgrepRules); err != nil {
			return nil, err
		}
		cfg = o.SemgrepRules
	} else if !o.Online {
		return nil, &engine.SkipError{Reason: skipOfflineNoRules}
	}
	out := filepath.Join(o.Scratch, outputFile)
	return []string{
		"scan",
		"--config", cfg,
		"--json", "--output", out,
		"--metrics=off",           // never send project metadata or rule hits to semgrep.dev
		"--disable-version-check", // no update check
		"--oss-only",              // never invoke the Pro engine / login flow
		"--quiet", "--no-rewrite-rule-ids",
		"--timeout", "30",
		"--max-target-bytes", strconv.Itoa(engine.MaxFileBytes),
		"--", t.Value,
	}, nil
}

// Run implements engine.Engine.
func (a *Adapter) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	a.root = t.Value
	return a.RunTool(ctx, a, t, o, emit, filepath.Join(o.Scratch, outputFile))
}

// result is the field allowlist for one semgrep results[] element.
type result struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Severity string `json:"severity"`
		Message  string `json:"message"`
		Lines    string `json:"lines"`
		Metadata struct {
			CWE        adapter.StringList `json:"cwe"`
			References adapter.StringList `json:"references"`
			Confidence string             `json:"confidence"`
			Category   string             `json:"category"`
		} `json:"metadata"`
	} `json:"extra"`
}

// Parse reads results[] from the JSON report.
func (a *Adapter) Parse(r io.Reader, emit func(domain.Finding) error) error {
	red := safety.NewRedactor()
	bad, err := adapter.StreamArray(r, "results", func(dec *json.Decoder) error {
		var res result
		if err := adapter.DecodeElement(dec, &res); err != nil {
			return err
		}
		f, ok := a.finding(&res, red)
		if !ok {
			return adapter.ErrSkipElement
		}
		return emit(f)
	})
	if err != nil {
		return fmt.Errorf("semgrep output: %w", err)
	}
	return adapter.BadCount("semgrep", bad)
}

func (a *Adapter) finding(res *result, red *safety.Redactor) (domain.Finding, bool) {
	if !checkIDRe.MatchString(res.CheckID) || strings.Contains(res.CheckID, "..") {
		return domain.Finding{}, false
	}
	rel, ok := adapter.RelLocation(a.root, res.Path)
	if !ok || res.Start.Line < 0 {
		return domain.Finding{}, false
	}
	sev, ok := adapter.Severity(res.Extra.Severity)
	if !ok {
		return domain.Finding{}, false
	}
	loc := rel
	if res.Start.Line > 0 {
		loc += ":" + strconv.Itoa(res.Start.Line)
	}
	assetKey := "repo:" + a.root
	conf := domain.Tentative
	if strings.EqualFold(res.Extra.Metadata.Confidence, "HIGH") {
		conf = domain.Firm
	}
	short := res.CheckID
	if i := strings.LastIndex(short, "."); i >= 0 {
		short = short[i+1:]
	}
	f := domain.Finding{
		AssetKey: assetKey, RuleID: "semgrep:" + res.CheckID, Engine: Name, Severity: sev, Confidence: conf,
		Location: loc, Status: domain.StatusOpen, Title: "semgrep: " + red.Clean(short, 120),
	}
	msg := red.Clean(res.Extra.Message, 2000)
	if msg == "" {
		f.WhatItIs = "semgrep rule " + res.CheckID + " matched (no message from semgrep)."
	} else {
		f.WhatItIs = msg + " (description from semgrep)"
	}
	f.WhyItMatters = "This check comes from the semgrep rule set in use; its severity is semgrep's own assessment. Pattern-based rules can match safe code, so confirm the data flow before fixing."
	f.HowToFix = "Follow the rule's guidance in the references; when none is given, review the matched lines and apply the standard mitigation for " + red.Clean(res.Extra.Metadata.Category, 40) + " issues."
	if res.Extra.Metadata.Category == "" {
		f.HowToFix = "Follow the rule's guidance in the references; when none is given, review the matched lines and remove the unsafe construct."
	}
	for _, c := range res.Extra.Metadata.CWE {
		// semgrep writes "CWE-79: Improper Neutralization ..."
		if i := strings.Index(c, ":"); i > 0 {
			c = c[:i]
		}
		if cwe := adapter.CWE(c); cwe != "" {
			f.CWE = cwe
			break
		}
	}
	f.CVEs = []string{}
	f.References = adapter.URLRefs(res.Extra.Metadata.References...)
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, loc)
	snippet := res.Extra.Lines
	if len(snippet) > domain.MaxEvidenceBytes {
		snippet = snippet[:domain.MaxEvidenceBytes]
	}
	if strings.TrimSpace(snippet) == "" {
		snippet = "(no snippet from semgrep)"
	}
	f.Evidence = []domain.Evidence{red.TextEvidence("file", loc, snippet)}
	return f, true
}

var _ adapter.Adapter = (*Adapter)(nil)
