package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// Limits for one plugin run (Section 5.8).
const (
	maxFindings  = 50000
	maxLineBytes = 1 << 20
	maxEvidence  = 10
	maxRefs      = 8
	maxLocation  = 1024
)

// LoadOptions controls Load.
type LoadOptions struct {
	Home string
	// SandboxMode is "required" (default) or "best-effort".
	SandboxMode string
	// Audit receives load-time integrity events.
	Audit func(action string, detail map[string]any)
}

// LoadEvent is one integrity decision made at load, carried to the
// audit trail by the caller.
type LoadEvent struct {
	Action string
	Detail map[string]any
}

// Load verifies every installed plugin and returns the newest version
// per name as an engine. Anything that fails verification — lock drift,
// a manifest that no longer parses, a missing sandbox under mode
// "required" — is skipped and reported through Audit, never run.
func Load(o LoadOptions) ([]engine.Engine, error) {
	l, err := LoadLock(o.Home)
	if err != nil {
		return nil, err
	}
	emit := o.Audit
	if emit == nil {
		emit = func(string, map[string]any) {}
	}
	sb := DetectSandbox()
	var out []engine.Engine
	for name, entry := range l.Latest() {
		id := name + "@" + entry.Version
		if err := Verify(o.Home, entry); err != nil {
			emit(audit.ActionPluginIntegrity, map[string]any{"plugin": id, "error": err.Error()})
			continue
		}
		raw, err := os.ReadFile(ManifestPath(o.Home, entry))
		if err != nil {
			emit(audit.ActionPluginIntegrity, map[string]any{"plugin": id, "error": err.Error()})
			continue
		}
		m, rules, err := ParseManifest(raw)
		if err != nil {
			emit(audit.ActionPluginIntegrity, map[string]any{"plugin": id, "error": err.Error()})
			continue
		}
		if m.Name != entry.Name || m.Version != entry.Version {
			emit(audit.ActionPluginIntegrity, map[string]any{"plugin": id, "error": "manifest name@version does not match the lock entry"})
			continue
		}
		if m.Capabilities.Network != entry.Capabilities.Network {
			emit(audit.ActionPluginIntegrity, map[string]any{"plugin": id, "error": "manifest capabilities do not match the lock entry"})
			continue
		}
		sandboxName := "none"
		if sb != nil {
			sandboxName = sb.Name()
		} else if o.SandboxMode != "best-effort" {
			emit(audit.ActionPluginIntegrity, map[string]any{"plugin": id, "error": "no sandbox wrapper (bwrap/sandbox-exec) and plugins.sandbox is required"})
			continue
		}
		out = append(out, &Engine{
			home: o.Home, entry: entry, manifest: m, rules: rules,
			sandbox: sb, sandboxName: sandboxName, bestEffort: sb == nil,
		})
	}
	return out, nil
}

// Engine runs one installed plugin as an engine.Engine.
type Engine struct {
	home        string
	entry       LockEntry
	manifest    *Manifest
	rules       []domain.Rule
	sandbox     Sandbox
	sandboxName string
	bestEffort  bool
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return "plugin:" + e.manifest.Name }

// Version implements engine.Versioned.
func (e *Engine) Version() string { return e.manifest.Version }

// PluginInfo reports name, version and sandbox for the scan record, so
// best-effort unsandboxed runs are audited per scan.
func (e *Engine) PluginInfo() (name, version, sandbox string) {
	if e.bestEffort {
		return e.manifest.Name, e.manifest.Version, "none (best-effort)"
	}
	return e.manifest.Name, e.manifest.Version, e.sandboxName
}

// Supports implements engine.Engine: the plugin's declared target types.
// Network plugins only run on URL/host targets, where same-origin
// brokered fetching is meaningful.
func (e *Engine) Supports(t domain.Target) bool {
	ok := false
	for _, s := range e.manifest.Supports {
		if domain.TargetType(s) == t.Type {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if e.manifest.Capabilities.Network == "broker" && t.Type != domain.TargetURL && t.Type != domain.TargetHost {
		return false
	}
	return true
}

// Plan implements engine.Engine.
func (e *Engine) Plan(_ context.Context, t domain.Target, _ engine.Options) (engine.Plan, error) {
	net := ""
	if e.manifest.Capabilities.Network == "broker" {
		net = ", brokered same-origin fetch"
	}
	return engine.Plan{
		Summary:     fmt.Sprintf("plugin %s %s: %d rules over %s%s", e.manifest.Name, e.manifest.Version, len(e.rules), t.Value, net),
		EstRequests: len(e.rules),
		Network:     e.manifest.Capabilities.Network == "broker",
	}, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	id := e.manifest.Name + "@" + e.manifest.Version
	// Re-verify at run time: the lock check at Load does not cover a
	// binary swapped mid-scan.
	if err := Verify(e.home, e.entry); err != nil {
		return &engine.SkipError{Reason: fmt.Sprintf("plugin %s integrity failure: %v", id, err)}
	}
	if o.Scratch == "" {
		return fmt.Errorf("plugin %s: no scratch directory", id)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Minute)
	}

	// The child's view of the world: a fresh scratch subdirectory as
	// cwd, HOME and TMPDIR. Nothing outside is writable.
	scratch := filepath.Join(o.Scratch, "plugin-"+e.manifest.Name)
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return err
	}

	var wrapper []string
	if e.sandbox != nil {
		// Non-path targets have no directory to bind: bind scratch
		// read-only as the "target" too (the later read-write bind
		// wins on bwrap; sandbox-exec unions the rules).
		bind := scratch
		if t.Type == domain.TargetPath {
			bind = t.Value
		}
		var err error
		wrapper, err = e.sandbox.Wrap(BinaryPath(e.home, e.entry), bind, scratch, false)
		if err != nil {
			return fmt.Errorf("plugin %s: %w", id, err)
		}
	} else if !e.bestEffort {
		return &engine.SkipError{Reason: fmt.Sprintf("plugin %s: no sandbox wrapper", id)}
	}
	if o.Log != nil {
		o.Log.Debug("plugin sandbox", "plugin", id, "sandbox", e.sandboxName, "best_effort", e.bestEffort)
	}

	// Broker, only for network plugins on URL/host targets.
	var broker *Broker
	brokerAddr := ""
	if e.manifest.Capabilities.Network == "broker" && (t.Type == domain.TargetURL || t.Type == domain.TargetHost) {
		origin, err := originForBroker(t)
		if err != nil {
			return &engine.SkipError{Reason: fmt.Sprintf("plugin %s: cannot broker target: %v", id, err)}
		}
		broker, err = NewBroker(BrokerConfig{Name: e.manifest.Name, Origin: origin, Max: 500, AnyScheme: t.Type == domain.TargetHost}, o.Dialer)
		if err != nil {
			return err
		}
		defer broker.Stop()
		brokerAddr = broker.Addr()
	}

	req, err := e.runRequest(t, o.Profile.Name, scratch, brokerAddr, deadline)
	if err != nil {
		return err
	}
	var base adapter.Base
	base.BinaryName = BinaryName(e.manifest.Name)
	base.Path = BinaryPath(e.home, e.entry)
	base.Setpgid = true
	base.Wrapper = wrapper
	base.UsePath(base.Path, e.manifest.Version)
	base.Stdin = bytes.NewReader(req)
	base.SetEnv = []string{"HOME=" + scratch, "TMPDIR=" + scratch}

	timeout := time.Until(deadline)
	if timeout <= 0 {
		timeout = time.Second
	}
	res, err := base.Exec(ctx, scratch, []string{"run"}, timeout)
	if err != nil {
		return fmt.Errorf("plugin %s: %w", id, err)
	}
	if res.ExitCode != 0 {
		tail := strings.TrimSpace(res.StderrTail)
		if o.Redactor != nil {
			tail = o.Redactor.Redact(tail)
		}
		return fmt.Errorf("plugin %s exited %d: %s", id, res.ExitCode, tail)
	}
	f, err := os.Open(res.StdoutPath)
	if err != nil {
		return fmt.Errorf("plugin %s produced no output: %w", id, err)
	}
	defer f.Close()
	return e.parse(t, o, io.LimitReader(f, adapter.MaxStdoutBytes), emit)
}

// runRequest builds the JSON run request fed to the child's stdin.
func (e *Engine) runRequest(t domain.Target, profile, scratch, broker string, deadline time.Time) ([]byte, error) {
	return json.Marshal(map[string]any{
		"protocol": ProtocolVersion,
		"target":   map[string]string{"type": string(t.Type), "value": t.Value},
		"scratch":  scratch,
		"profile":  profile,
		"deadline": deadline.UTC().Format(time.RFC3339),
		"broker":   broker,
	})
}

// originForBroker derives the broker's pinned origin from the target.
func originForBroker(t domain.Target) (string, error) {
	if t.Type == domain.TargetURL {
		u, err := url.Parse(t.Value)
		if err != nil {
			return "", err
		}
		u.Path, u.RawQuery, u.Fragment = "", "", ""
		return u.String(), nil
	}
	return "https://" + t.Value, nil
}

// rawFinding is one JSONL line from the child. Unknown fields are
// rejected so a plugin cannot smuggle enrichment past the parser.
type rawFinding struct {
	Rule       string   `json:"rule"`
	Location   string   `json:"location"`
	Confidence string   `json:"confidence"`
	CVEs       []string `json:"cves"`
	References []string `json:"references"`
	Evidence   []rawEv  `json:"evidence"`
}

type rawEv struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Text     string `json:"text"`
}

// parse validates the child's JSONL and emits domain findings. Rule
// text comes from the signed manifest, never the child; KEV/EPSS/CVSS
// from the plugin are impossible (unknown fields are rejected) — scnr
// computes enrichment from CVEs itself.
func (e *Engine) parse(t domain.Target, o engine.Options, r io.Reader, emit engine.EmitFunc) error {
	id := e.manifest.Name + "@" + e.manifest.Version
	rules := map[string]domain.Rule{}
	for _, r := range e.rules {
		short, _ := strings.CutPrefix(r.ID, "plugin."+e.manifest.Name+".")
		rules[short] = r
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLineBytes+1)
	count := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if len(line) > maxLineBytes {
			return fmt.Errorf("plugin %s: finding line over %d bytes", id, maxLineBytes)
		}
		var raw rawFinding
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("plugin %s: bad finding line: %w", id, err)
		}
		count++
		if count > maxFindings {
			return fmt.Errorf("plugin %s: more than %d findings", id, maxFindings)
		}
		rule, ok := rules[raw.Rule]
		if !ok {
			return fmt.Errorf("plugin %s: undeclared rule %q", id, raw.Rule)
		}
		loc, ok := normaliseLocation(t, raw.Location)
		if !ok {
			continue // out-of-target locations are dropped, not failed
		}
		sev, _ := domain.ParseSeverity(rule.Severity)
		f := domain.Finding{
			AssetKey:     t.AssetKey(),
			RuleID:       rule.ID,
			Title:        rule.Title,
			Severity:     sev,
			Confidence:   parseConfidence(raw.Confidence),
			WhatItIs:     rule.WhatItIs,
			WhyItMatters: rule.WhyItMatters,
			HowToFix:     rule.HowToFix,
			CWE:          rule.CWE,
			Location:     loc,
			Status:       domain.StatusOpen,
		}
		f.References = append(f.References, rule.References...)
		// Child-supplied references pass the same http(s) filter as
		// manifest references (which URLRefs already applied).
		for _, ref := range adapter.URLRefs(raw.References...) {
			if len(f.References) >= maxRefs {
				break
			}
			f.References = append(f.References, ref)
		}
		for _, c := range raw.CVEs {
			if validCVE(c) {
				f.CVEs = append(f.CVEs, c)
			}
		}
		red := o.Redactor
		if red == nil {
			red = safety.NewRedactor()
		}
		for i, ev := range raw.Evidence {
			if i >= maxEvidence {
				break
			}
			f.Evidence = append(f.Evidence, red.TextEvidence(ev.Kind, ev.Location, ev.Text))
		}
		if err := emit(f); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("plugin %s: reading findings: %w", id, err)
	}
	return nil
}

// normaliseLocation constrains finding locations to the scanned target:
// relative paths under a path target (absolute paths inside the target
// are relativised), same-origin URLs under a URL/host target, anything
// short elsewhere.
func normaliseLocation(t domain.Target, loc string) (string, bool) {
	if loc == "" {
		return "", true
	}
	if len(loc) > maxLocation {
		return "", false
	}
	switch t.Type {
	case domain.TargetPath:
		p := loc
		if filepath.IsAbs(p) {
			rel, err := filepath.Rel(t.Value, p)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", false
			}
			p = rel
		}
		if p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
			return "", false
		}
		return filepath.Clean(p), true
	case domain.TargetURL, domain.TargetHost:
		var base *url.URL
		if t.Type == domain.TargetURL {
			var err error
			base, err = url.Parse(t.Value)
			if err != nil {
				return "", false
			}
		} else {
			base = &url.URL{Scheme: "https", Host: t.Value}
		}
		u, err := url.Parse(loc)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		if !strings.EqualFold(u.Hostname(), base.Hostname()) || u.Port() != base.Port() {
			return "", false
		}
		u.Fragment = ""
		return u.String(), true
	default:
		return loc, true
	}
}

func parseConfidence(s string) domain.Confidence {
	switch strings.ToLower(s) {
	case "firm":
		return domain.Firm
	case "confirmed":
		return domain.Confirmed
	default:
		return domain.Tentative
	}
}

func validCVE(s string) bool {
	if !strings.HasPrefix(s, "CVE-") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(s, "CVE-"), "-")
	return len(parts) == 2 && len(parts[0]) == 4 && len(parts[1]) >= 4
}
