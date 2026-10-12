// Package engine defines the Engine interface, the Registry of engines and
// the Runner that executes them with bounded concurrency.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/safety"
)

// Options are passed to every engine for a scan.
type Options struct {
	Profile Profile
	Limiter *safety.Limits
	HTTP    *http.Client
	Scope   *safety.Scope
	Dialer  *safety.Dialer
	Scratch string
	Log     *slog.Logger
	Online  bool
	// Ports overrides the profile's port list (from --ports).
	Ports []int
	// Redactor is applied before any Evidence is created.
	Redactor *safety.Redactor
	// SecretKey is the per-install key (safety.LoadOrCreateSecret) used to
	// fingerprint secret values; engines that emit secret evidence require it.
	SecretKey []byte
	// TemplatesDir is an optional user template directory (--templates)
	// merged with the embedded webscan templates.
	TemplatesDir string
	// NucleiTemplatesDir is the local nuclei template corpus the adapter
	// passes explicitly (scnr.yaml tools.nuclei_templates). Empty means nuclei
	// uses its own default directory, which it may populate from the network
	// on first run.
	NucleiTemplatesDir string
	// SemgrepRules is a local semgrep ruleset path or directory passed as
	// --config (scnr.yaml tools.semgrep_rules). Empty means the registry
	// pack p/default, which semgrep fetches from semgrep.dev.
	SemgrepRules string
	// Intrusive permits active checks (4d) for this target. Set per plan
	// by RunScan from the IntrusiveGate outcome, never from the flag
	// alone.
	Intrusive bool
	// Auth carries authenticated-scan credentials. The HTTP client's
	// transport applies them to the authorised origin only.
	Auth *safety.AuthMaterial
	// Stats, when non-nil, receives the engine's run telemetry once per
	// Run call. RunScan collects it for the scan record and report
	// banner. Called synchronously; implementations must not block long.
	Stats func(Stats)
}

// Stats is an engine's run telemetry: requests beyond the engine's
// passive baseline, split by class.
type Stats struct {
	// Probes counts active probe requests (DAST).
	Probes int
	// Crawl counts crawler discovery fetches (DAST).
	Crawl int
}

// Plan sizes the work before consent.
type Plan struct {
	Summary     string
	EstRequests int
	EstDuration time.Duration
	Network     bool
}

// EmitFunc receives findings as they are produced.
type EmitFunc func(domain.Finding) error

// Engine is a native check or an adapter.
type Engine interface {
	Name() string
	Supports(t domain.Target) bool
	Plan(ctx context.Context, t domain.Target, o Options) (Plan, error)
	Run(ctx context.Context, t domain.Target, o Options, emit EmitFunc) error
}

// Versioned is implemented by engines backed by an external tool; the
// Runner records the version on the EngineRun after Run returns.
type Versioned interface {
	Version() string
}

// SkipError lets an engine report that it did not run (e.g. offline). The
// scan is marked Partial but not failed.
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return "skipped: " + e.Reason }

// PartialError lets an engine report that it ran and emitted its findings
// but could not cover everything it was asked to check (e.g. ranges the
// offline matcher cannot evaluate). The scan is marked Partial but not
// failed; the engine's findings stand.
type PartialError struct{ Reason string }

func (e *PartialError) Error() string { return "partial: " + e.Reason }

// Registry holds engines by name.
type Registry struct {
	engines map[string]Engine
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{engines: map[string]Engine{}} }

// Register adds an engine; duplicate names panic (programmer error).
func (r *Registry) Register(e Engine) {
	if _, dup := r.engines[e.Name()]; dup {
		panic("duplicate engine " + e.Name())
	}
	r.engines[e.Name()] = e
}

// Get returns an engine by name.
func (r *Registry) Get(name string) (Engine, bool) {
	e, ok := r.engines[name]
	return e, ok
}

// Names lists registered engines, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.engines))
	for n := range r.engines {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Select returns the engines applicable to t under the profile and the
// include/skip filters, sorted by name.
func (r *Registry) Select(t domain.Target, p Profile, only, skip []string) ([]Engine, error) {
	onlySet := toSet(only)
	skipSet := toSet(skip)
	for n := range onlySet {
		if _, ok := r.engines[n]; !ok {
			return nil, fmt.Errorf("unknown engine %q (have %v)", n, r.Names())
		}
	}
	var out []Engine
	for _, n := range r.Names() {
		e := r.engines[n]
		if len(onlySet) > 0 && !onlySet[n] {
			continue
		}
		if skipSet[n] || !p.allowsEngine(n) || !e.Supports(t) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func toSet(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		if s != "" {
			m[s] = true
		}
	}
	return m
}
