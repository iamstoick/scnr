package doctor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/store"
)

func TestRunChecks(t *testing.T) {
	home := t.TempDir()
	s, err := store.Open(filepath.Join(home, "scnr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	checks, err := Run(ctx, Options{Home: home, Store: s, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Check{}
	for _, c := range checks {
		byName[c.Name] = c
	}
	if byName["config"].Status != Warn || byName["database"].Status != OK || byName["vulndb kev"].Status != Missing || byName["vulndb epss"].Status != Missing {
		t.Fatalf("%+v", byName)
	}
	if _, ok := byName["tool nmap"]; !ok {
		t.Fatal("tool rows missing")
	}
	if !strings.HasPrefix(byName["disk "+home].Detail, "") || byName["disk "+home].Status == "" {
		t.Fatal("disk check missing")
	}
	// Fresh vs old vulndb.
	s.ReplaceKEV(ctx, []store.KEVEntry{{CVE: "CVE-1", Added: "x"}}, "v")
	checks, _ = Run(ctx, Options{Home: home, Store: s, Now: func() time.Time { return time.Now() }})
	for _, c := range checks {
		if c.Name == "vulndb kev" && c.Status != OK {
			t.Fatalf("fresh kev should be OK: %+v", c)
		}
	}
	checks, _ = Run(ctx, Options{Home: home, Store: s, Now: func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }})
	for _, c := range checks {
		if c.Name == "vulndb kev" && c.Status != Old {
			t.Fatalf("stale kev should be OLD: %+v", c)
		}
	}
	// Config states.
	cfg := filepath.Join(home, "scnr.yaml")
	os.WriteFile(cfg, []byte("nope: 1\n"), 0o600)
	checks, _ = Run(ctx, Options{Home: home, ConfigPath: cfg, Store: s})
	for _, c := range checks {
		if c.Name == "config" && c.Status != Fail {
			t.Fatalf("invalid config should FAIL: %+v", c)
		}
	}
	// nuclei templates: warns when no local corpus is configured (nuclei would
	// download one on first run), OK when the configured directory exists.
	nucleiOnly := map[string]Detector{"nuclei": stubDetector{}}
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true}\n"), 0o600)
	checks, _ = Run(ctx, Options{Home: home, ConfigPath: cfg, Store: s, Adapters: nucleiOnly})
	if c := find(checks, "nuclei templates"); c.Status != Warn || !strings.Contains(c.Detail, "first run") || !strings.Contains(c.Detail, "tools.nuclei_templates") {
		t.Fatalf("unconfigured nuclei templates: %+v", c)
	}
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true}\ntools: {nuclei_templates: "+filepath.Join(home, "missing")+"}\n"), 0o600)
	checks, _ = Run(ctx, Options{Home: home, ConfigPath: cfg, Store: s, Adapters: nucleiOnly})
	if c := find(checks, "nuclei templates"); c.Status != Fail {
		t.Fatalf("missing nuclei templates dir: %+v", c)
	}
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true}\ntools: {nuclei_templates: "+home+"}\n"), 0o600)
	checks, _ = Run(ctx, Options{Home: home, ConfigPath: cfg, Store: s, Adapters: nucleiOnly})
	if c := find(checks, "nuclei templates"); c.Status != OK || !strings.Contains(c.Detail, "-t") {
		t.Fatalf("configured nuclei templates: %+v", c)
	}
	if c := find(Run2(ctx, Options{Home: home, ConfigPath: cfg, Store: s}), "nuclei templates"); c.Name != "" {
		t.Fatal("nuclei templates row without a nuclei adapter")
	}
	os.WriteFile(cfg, []byte("nope: 1\n"), 0o600)
	checks, _ = Run(ctx, Options{Home: home, ConfigPath: cfg, Store: s})
	var buf bytes.Buffer
	Print(&buf, checks)
	if !strings.Contains(buf.String(), "CHECK") || !strings.Contains(buf.String(), "database") {
		t.Fatal(buf.String())
	}
	buf.Reset()
	PrintInstallGuide(&buf)
	if !strings.Contains(buf.String(), "never runs these") || !strings.Contains(buf.String(), "trivy") {
		t.Fatal(buf.String())
	}
	if len(ListsOutbound()) != 4 {
		t.Fatal("outbound list")
	}
	if len(ToolOutbound()) != 4 {
		t.Fatal("tool outbound list")
	}
	// semgrep rules: warns about the registry fetch when unset, OK when a
	// local ruleset exists, FAIL when the configured path is missing.
	semgrepOnly := map[string]Detector{"semgrep": stubDetector{}}
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true}\n"), 0o600)
	if c := find(Run2(ctx, Options{Home: home, ConfigPath: cfg, Store: s, Adapters: semgrepOnly}), "semgrep rules"); c.Status != Warn || !strings.Contains(c.Detail, "semgrep.dev") || !strings.Contains(c.Detail, "tools.semgrep_rules") {
		t.Fatalf("unconfigured semgrep rules: %+v", c)
	}
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true}\ntools: {semgrep_rules: "+filepath.Join(home, "missing.yaml")+"}\n"), 0o600)
	if c := find(Run2(ctx, Options{Home: home, ConfigPath: cfg, Store: s, Adapters: semgrepOnly}), "semgrep rules"); c.Status != Fail {
		t.Fatalf("missing semgrep rules: %+v", c)
	}
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true}\ntools: {semgrep_rules: "+home+"}\n"), 0o600)
	if c := find(Run2(ctx, Options{Home: home, ConfigPath: cfg, Store: s, Adapters: semgrepOnly}), "semgrep rules"); c.Status != OK || !strings.Contains(c.Detail, "--config") {
		t.Fatalf("configured semgrep rules: %+v", c)
	}
	if c := find(Run2(ctx, Options{Home: home, ConfigPath: cfg, Store: s}), "semgrep rules"); c.Name != "" {
		t.Fatal("semgrep rules row without a semgrep adapter")
	}
}

type stubDetector struct{}

func (stubDetector) Detect(context.Context) (adapter.ToolInfo, error) {
	return adapter.ToolInfo{Reason: "not found on PATH"}, nil
}
func (stubDetector) MinVersion() string { return "3.0.0" }

func find(checks []Check, name string) Check {
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

// Run2 drops Run's error for one-line assertions.
func Run2(ctx context.Context, o Options) []Check {
	checks, _ := Run(ctx, o)
	return checks
}

// --online without an injected client is an error rather than a probe
// through http.DefaultClient.
func TestOnlineNeedsClient(t *testing.T) {
	_, err := Run(context.Background(), Options{Home: t.TempDir(), Online: true})
	if err == nil || !strings.Contains(err.Error(), "HTTP client") {
		t.Fatalf("want no-client error, got %v", err)
	}
}
