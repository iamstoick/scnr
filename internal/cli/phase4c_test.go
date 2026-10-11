package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/audit"
	cloudaws "github.com/iamstoick/scnr/internal/engine/cloud/aws"
	"github.com/iamstoick/scnr/internal/engine/cloud/aws/awstest"
	"github.com/iamstoick/scnr/internal/sched"
	"github.com/iamstoick/scnr/internal/store"
	"github.com/iamstoick/scnr/internal/wizard"
)

// writeAckConfig writes a scope file with the standing acknowledgment and
// points the harness at it. Schedules cannot carry --ack-authorized, so
// daemon runs need this file. scope replaces the default empty scope
// block when non-empty.
func writeAckConfig(t *testing.T, h *harness, scope string) {
	t.Helper()
	if scope == "" {
		scope = "scope:\n  allow: []\n  deny: []\n"
	}
	cfg := filepath.Join(h.home, "scnr.yaml")
	body := "authorization: {acknowledged: true, by: t}\n" + scope
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	h.app.ConfigPath = cfg
}

// backdate marks a schedule due in the past through the real store.
func backdate(t *testing.T, h *harness, name string, next time.Time) {
	t.Helper()
	s := h.store(t)
	if err := s.MarkScheduleRun(context.Background(), name, time.Now(), "", "", next); err != nil {
		t.Fatal(err)
	}
}

func getSchedule(t *testing.T, h *harness, name string) store.Schedule {
	t.Helper()
	s, err := h.store(t).GetSchedule(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Schedule CRUD plus the add-time forbidden list (C1, C3, C7).
func TestScheduleCRUD(t *testing.T) {
	h := newHarness(t)
	if code := h.run(t, "schedule", "add", "--name", "weekly", "--cron", "0 2 * * 1", "--", "scan", "10.0.0.0/24", "--profile", "standard"); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "schedule", "add", "--name", "weekly", "--cron", "@daily", "--", "scan", "."); code != ExitUsage || !strings.Contains(h.stderr.String(), "already exists") {
		t.Fatalf("dup: %d %s", code, h.stderr.String())
	}
	bad := []struct {
		name string
		args []string
		want string
	}{
		{"bad-name", []string{"schedule", "add", "--name", "Bad Name", "--cron", "@daily", "--", "scan", "."}, "must match"},
		{"fast-cron", []string{"schedule", "add", "--name", "f", "--cron", "* * * * *", "--", "scan", "."}, "more often than once an hour"},
		{"bad-cron", []string{"schedule", "add", "--name", "f", "--cron", "nope", "--", "scan", "."}, "cron"},
		{"no-scan", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "ping", "."}, `must start with "scan"`},
		{"no-target", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", "--profile", "quick"}, "at least one target"},
		{"ack", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", ".", "--ack-authorized"}, "schedules refuse --ack-authorized"},
		{"ack-false", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", ".", "--ack-authorized=false"}, "schedules refuse --ack-authorized"},
		{"non-interactive", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", ".", "--non-interactive"}, "schedules refuse --non-interactive"},
		{"header", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", "https://x.example", "--header", "A:b"}, "schedules refuse --header"},
		{"cookie", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", "https://x.example", "--cookie", "a=b"}, "schedules refuse --cookie"},
		{"unknown", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", ".", "--frobnicate"}, "unknown flag"},
		{"creds-url", []string{"schedule", "add", "--name", "f", "--cron", "@daily", "--", "scan", "https://user:pw@example.com"}, "carries URL credentials"},
	}
	for _, tc := range bad {
		if code := h.run(t, tc.args...); code != ExitUsage || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%s: %d %s (want %q)", tc.name, code, h.stderr.String(), tc.want)
		}
	}
	if code := h.run(t, "schedule", "list"); code != ExitOK || !strings.Contains(h.stdout.String(), "weekly") {
		t.Fatalf("list: %d %s", code, h.stdout.String())
	}
	if code := h.run(t, "schedule", "show", "weekly"); code != ExitOK {
		t.Fatalf("show: %d %s", code, h.stderr.String())
	} else if out := h.stdout.String(); !strings.Contains(out, "10.0.0.0/24") || !strings.Contains(out, "--profile") {
		t.Fatalf("show hides argv: %q", out)
	}
	if code := h.run(t, "schedule", "show", "missing"); code != ExitUsage || !strings.Contains(h.stderr.String(), "no schedule") {
		t.Fatalf("show missing: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "schedule", "disable", "weekly"); code != ExitOK {
		t.Fatalf("disable: %d %s", code, h.stderr.String())
	}
	if s := getSchedule(t, h, "weekly"); s.Enabled {
		t.Fatal("still enabled")
	}
	if code := h.run(t, "schedule", "enable", "weekly"); code != ExitOK {
		t.Fatalf("enable: %d %s", code, h.stderr.String())
	}
	if s := getSchedule(t, h, "weekly"); !s.Enabled || !s.NextRun.After(time.Now()) {
		t.Fatalf("enable: %+v", s)
	}
	if code := h.run(t, "schedule", "remove", "weekly"); code != ExitOK {
		t.Fatalf("remove: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "schedule", "remove", "weekly"); code != ExitUsage {
		t.Fatalf("remove missing: %d", code)
	}
	if code := h.run(t, "schedule", "list"); code != ExitOK || !strings.Contains(h.stdout.String(), "no schedules") {
		t.Fatalf("list after remove: %d %s", code, h.stdout.String())
	}
	// The add is audited with the full argv.
	found := false
	for _, r := range h.auditRows(t) {
		if r.Action != audit.ActionSchedule {
			continue
		}
		var d map[string]any
		_ = json.Unmarshal(r.Detail, &d)
		if d["op"] == "add" && d["name"] == "weekly" {
			found = true
			if args, _ := d["args"].([]any); len(args) == 0 || args[0] != "scan" {
				t.Fatalf("add audit args: %v", d["args"])
			}
		}
	}
	if !found {
		t.Fatal("no schedule add audit row")
	}
}

// A due schedule runs end to end under `daemon run --once`: real scan,
// stdout line, status persisted, next advanced, scans.meta attributed.
// Secrets-only and offline: no network.
func TestDaemonOnceRunsDueSchedule(t *testing.T) {
	h := newHarness(t)
	writeAckConfig(t, h, "")
	repo := fixtureRepo(t)
	out := filepath.Join(t.TempDir(), "out")
	add := []string{"schedule", "add", "--name", "nightly", "--cron", "@daily", "--",
		"scan", repo, "--profile", "quick", "--engines", "secrets", "--offline"}
	if code := h.run(t, add...); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	backdate(t, h, "nightly", time.Now().Add(-time.Hour))
	if code := h.run(t, "daemon", "run", "--once", "--out", out); code != ExitOK {
		t.Fatalf("once: %d %s", code, h.stderr.String())
	}
	if out := h.stdout.String(); !strings.Contains(out, "nightly: ok scan=") {
		t.Fatalf("stdout line: %q", out)
	}
	s := getSchedule(t, h, "nightly")
	if s.LastStatus != "ok" || s.LastScanID == "" || !s.NextRun.After(time.Now()) {
		t.Fatalf("row: %+v", s)
	}
	got, err := h.store(t).GetScan(context.Background(), s.LastScanID)
	if err != nil || got.Schedule != "nightly" {
		t.Fatalf("scan schedule attribution: %+v %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(out, s.LastScanID, "report.json")); err != nil {
		t.Fatalf("report: %v", err)
	}
	// A stored --out wins over the daemon default.
	h2 := newHarness(t)
	writeAckConfig(t, h2, "")
	custom := filepath.Join(t.TempDir(), "custom")
	add2 := []string{"schedule", "add", "--name", "c", "--cron", "@daily", "--",
		"scan", repo, "--profile", "quick", "--engines", "secrets", "--offline", "--out", custom}
	if code := h2.run(t, add2...); code != ExitOK {
		t.Fatalf("add2: %d %s", code, h2.stderr.String())
	}
	backdate(t, h2, "c", time.Now().Add(-time.Hour))
	if code := h2.run(t, "daemon", "run", "--once", "--out", filepath.Join(t.TempDir(), "ignored")); code != ExitOK {
		t.Fatalf("once2: %d %s", code, h2.stderr.String())
	}
	row := getSchedule(t, h2, "c")
	if _, err := os.Stat(filepath.Join(custom, row.LastScanID, "report.json")); err != nil {
		t.Fatalf("custom out: %v", err)
	}
}

// The daemon never prompts: a public target without verification is
// refused with the ownership code (which only happens when the gate has
// no consent func), the refusal is audited, and --once still exits 0.
// (C2.) The harness TTY is forced on to prove the daemon ignores it.
func TestDaemonHasNoConsentFunc(t *testing.T) {
	h := newHarness(t)
	h.app.IsTTY = true
	writeAckConfig(t, h, "scope:\n  allow: [8.8.8.8]\n  deny: []\n")
	add := []string{"schedule", "add", "--name", "pub", "--cron", "@daily", "--",
		"scan", "8.8.8.8", "--profile", "quick", "--offline"}
	if code := h.run(t, add...); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	backdate(t, h, "pub", time.Now().Add(-time.Hour))
	if code := h.run(t, "daemon", "run", "--once"); code != ExitOK {
		t.Fatalf("once: %d %s", code, h.stderr.String())
	}
	if out := h.stdout.String(); strings.Contains(out, "Type \"yes\"") || strings.Contains(out, "type ") && strings.Contains(out, " back") {
		t.Fatalf("daemon prompted: %q", out)
	}
	s := getSchedule(t, h, "pub")
	if s.LastStatus != "refused: E_OWNERSHIP_REQUIRED" || s.LastScanID != "" || !s.NextRun.After(time.Now()) {
		t.Fatalf("row: %+v", s)
	}
	found := false
	for _, r := range h.auditRows(t) {
		if r.Action == audit.ActionGateRefused {
			found = true
		}
	}
	if !found {
		t.Fatal("no gate_refused audit row")
	}
}

// A scope file that breaks between add and run skips the run (audited)
// instead of failing the daemon.
func TestDaemonBrokenScopeSkipped(t *testing.T) {
	h := newHarness(t)
	writeAckConfig(t, h, "")
	repo := fixtureRepo(t)
	add := []string{"schedule", "add", "--name", "b", "--cron", "@daily", "--",
		"scan", repo, "--profile", "quick", "--engines", "secrets", "--offline"}
	if code := h.run(t, add...); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	if err := os.WriteFile(h.app.ConfigPath, []byte("authorization: [broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backdate(t, h, "b", time.Now().Add(-time.Hour))
	if code := h.run(t, "daemon", "run", "--once"); code != ExitOK {
		t.Fatalf("once: %d %s", code, h.stderr.String())
	}
	if s := getSchedule(t, h, "b"); !strings.HasPrefix(s.LastStatus, "skipped: broken scope file") {
		t.Fatalf("row: %+v", s)
	}
	found := false
	for _, r := range h.auditRows(t) {
		if r.Action == audit.ActionScheduleSkipped {
			found = true
		}
	}
	if !found {
		t.Fatal("no schedule_skipped audit row")
	}
}

// Authorization removed between add and run refuses the run: the daemon
// re-reads the scope file every time instead of trusting add-time state.
func TestDaemonReloadsScope(t *testing.T) {
	h := newHarness(t)
	writeAckConfig(t, h, "")
	repo := fixtureRepo(t)
	add := []string{"schedule", "add", "--name", "r", "--cron", "@daily", "--",
		"scan", repo, "--profile", "quick", "--engines", "secrets", "--offline"}
	if code := h.run(t, add...); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	if err := os.Remove(h.app.ConfigPath); err != nil {
		t.Fatal(err)
	}
	backdate(t, h, "r", time.Now().Add(-time.Hour))
	if code := h.run(t, "daemon", "run", "--once"); code != ExitOK {
		t.Fatalf("once: %d %s", code, h.stderr.String())
	}
	if s := getSchedule(t, h, "r"); s.LastStatus != "refused: E_ACK_REQUIRED" {
		t.Fatalf("row: %+v", s)
	}
}

// A row injected straight into the database with forbidden argv is refused
// at run time by re-validation, exactly like at add time. (C3.)
func TestDaemonRefusesInjectedArgs(t *testing.T) {
	h := newHarness(t)
	writeAckConfig(t, h, "")
	s := h.store(t)
	err := s.CreateSchedule(context.Background(), store.Schedule{
		Name: "evil", Cron: "@daily", Args: []string{"scan", ".", "--ack-authorized"},
		Enabled: true, CreatedBy: "t", CreatedAt: time.Now(), NextRun: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := h.run(t, "daemon", "run", "--once"); code != ExitOK {
		t.Fatalf("once: %d %s", code, h.stderr.String())
	}
	row := getSchedule(t, h, "evil")
	if !strings.HasPrefix(row.LastStatus, "skipped: bad args") || row.LastScanID != "" {
		t.Fatalf("row: %+v", row)
	}
}

// A second daemon (or --once) while the lock is held exits 2. (C1.)
func TestDaemonLockContention(t *testing.T) {
	h := newHarness(t)
	release, err := sched.SystemLocker.TryLock(filepath.Join(h.home, sched.LockFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if code := h.run(t, "daemon", "run", "--once"); code != ExitUsage || !strings.Contains(h.stderr.String(), "already running") {
		t.Fatalf("locked: %d %s", code, h.stderr.String())
	}
}

// A failed notify is audited, not fatal: the run still exits 0.
func TestDaemonNotifyFailureAudited(t *testing.T) {
	h := newHarness(t)
	writeAckConfig(t, h, "")
	repo := fixtureRepo(t)
	add := []string{"schedule", "add", "--name", "n", "--cron", "@daily", "--",
		"scan", repo, "--profile", "quick", "--engines", "secrets", "--offline"}
	if code := h.run(t, add...); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	backdate(t, h, "n", time.Now().Add(-time.Hour))
	// Closed loopback port: connection refused, no listener needed.
	if code := h.run(t, "daemon", "run", "--once", "--notify-url", "http://127.0.0.1:1/hook"); code != ExitOK {
		t.Fatalf("once: %d %s", code, h.stderr.String())
	}
	if s := getSchedule(t, h, "n"); s.LastStatus != "ok" {
		t.Fatalf("row: %+v", s)
	}
	found := false
	for _, r := range h.auditRows(t) {
		if r.Action != audit.ActionSchedule {
			continue
		}
		var d map[string]any
		_ = json.Unmarshal(r.Detail, &d)
		if d["op"] == "notify-failed" {
			found = true
		}
	}
	if !found {
		t.Fatal("no notify-failed audit row")
	}
}

// A live webhook receives the summary with the pinned keys. (Acceptance.)
func TestDaemonOnceNotify(t *testing.T) {
	h := newHarness(t)
	writeAckConfig(t, h, "")
	repo := fixtureRepo(t)
	add := []string{"schedule", "add", "--name", "w", "--cron", "@daily", "--",
		"scan", repo, "--profile", "quick", "--engines", "secrets", "--offline"}
	if code := h.run(t, add...); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	backdate(t, h, "w", time.Now().Add(-time.Hour))
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	if code := h.run(t, "daemon", "run", "--once", "--notify-url", srv.URL+"/hook"); code != ExitOK {
		t.Fatalf("once: %d %s", code, h.stderr.String())
	}
	for _, k := range []string{"schema_version", "schedule", "scan_id", "started_at", "finished_at", "profile", "targets", "score", "grade", "counts", "partial", "exit_code", "report_paths"} {
		if _, ok := got[k]; !ok {
			t.Errorf("body lacks %q: %v", k, got)
		}
	}
	if got["schedule"] != "w" || got["profile"] != "quick" {
		t.Errorf("body: %v", got)
	}
	if _, ok := got["findings"]; ok {
		t.Error("body carries findings")
	}
}

// AWS credentials resolve per run: removing the shared credentials file
// between two --once runs turns the second into a refusal. A cached
// session would have kept succeeding. (C6.)
func TestDaemonRebuildsCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ROLE_ARN", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	creds := filepath.Join(dir, "credentials")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
	if err := os.WriteFile(creds, []byte("[default]\naws_access_key_id = "+fakeAWSKey+"\naws_secret_access_key = "+fakeAWSSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	srv := awstest.New(t, awstest.Fixture{})
	h.app.AWSEndpoint = srv.URL
	writeCloudConfig(t, h, awstest.DefaultAccount)
	add := []string{"schedule", "add", "--name", "aws", "--cron", "@daily", "--",
		"scan", "aws://", "--profile", "quick", "--engines", cloudaws.Name}
	if code := h.run(t, add...); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	backdate(t, h, "aws", time.Now().Add(-time.Hour))
	if code := h.run(t, "daemon", "run", "--once"); code != ExitOK {
		t.Fatalf("once1: %d %s", code, h.stderr.String())
	}
	if s := getSchedule(t, h, "aws"); s.LastStatus != "ok" || s.LastScanID == "" {
		t.Fatalf("row1: %+v", s)
	}
	if err := os.Remove(creds); err != nil {
		t.Fatal(err)
	}
	backdate(t, h, "aws", time.Now().Add(-time.Hour))
	if code := h.run(t, "daemon", "run", "--once"); code != ExitOK {
		t.Fatalf("once2: %d %s", code, h.stderr.String())
	}
	if s := getSchedule(t, h, "aws"); !strings.HasPrefix(s.LastStatus, "refused:") {
		t.Fatalf("row2: %+v", s)
	}
}

// Doctor reports the daemon lock state and schedules due soon.
func TestDoctorDaemon(t *testing.T) {
	h := newHarness(t)
	if code := h.run(t, "doctor"); code != ExitOK {
		t.Fatalf("doctor: %d %s", code, h.stderr.String())
	}
	if out := h.stdout.String(); !strings.Contains(out, "daemon") || !strings.Contains(out, "not running") || !strings.Contains(out, "none stored") {
		t.Fatalf("doctor: %q", out)
	}
	if code := h.run(t, "schedule", "add", "--name", "d", "--cron", "@hourly", "--", "scan", "."); code != ExitOK {
		t.Fatalf("add: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "doctor"); code != ExitOK {
		t.Fatalf("doctor2: %d %s", code, h.stderr.String())
	}
	if out := h.stdout.String(); !strings.Contains(out, "1 due in 24h: d @") {
		t.Fatalf("doctor2: %q", out)
	}
	release, err := sched.SystemLocker.TryLock(filepath.Join(h.home, sched.LockFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if code := h.run(t, "doctor"); code != ExitOK {
		t.Fatalf("doctor3: %d %s", code, h.stderr.String())
	}
	if out := h.stdout.String(); !strings.Contains(out, "running (pid ") {
		t.Fatalf("doctor3: %q", out)
	}
}

// The per-run timeout is profile EngineTimeout × engines + 10 minutes;
// deep (no per-engine timeout) uses the standard equivalent so daemon
// runs stay bounded.
func TestRunTimeout(t *testing.T) {
	h := newHarness(t)
	repo := fixtureRepo(t)
	mk := func(profile string) wizard.ScanRequest {
		return wizard.ScanRequest{Targets: []string{repo}, Profile: profile, Engines: []string{"secrets"}}
	}
	// quick: 2m × 1 + 10m; standard: 10m × 1 + 10m; deep: 10m × 1 + 10m.
	if got := runTimeout(context.Background(), h.app, mk("quick")); got != 12*time.Minute {
		t.Fatalf("quick: %v", got)
	}
	if got := runTimeout(context.Background(), h.app, mk("standard")); got != 20*time.Minute {
		t.Fatalf("standard: %v", got)
	}
	if got := runTimeout(context.Background(), h.app, mk("deep")); got != 20*time.Minute {
		t.Fatalf("deep: %v", got)
	}
	if got := runTimeout(context.Background(), h.app, mk("bogus")); got != 20*time.Minute {
		t.Fatalf("bogus profile: %v", got)
	}
}
