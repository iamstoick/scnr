package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/engine/webscan"
	"github.com/iamstoick/scnr/internal/safety"
)

func writeIntrusiveConfig(t *testing.T, h *harness, intrusiveAllow string) {
	t.Helper()
	cfg := filepath.Join(h.home, "scnr.yaml")
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true, by: t}\nscope:\n  allow: []\n  deny: []\n  intrusive_allow: ["+intrusiveAllow+"]\n"), 0o600)
	h.app.ConfigPath = cfg
}

// Schedules accept --allow-intrusive and --auth-file (re-checked at run
// time) and refuse --header/--cookie literals, now that the flags exist.
func TestScheduleArgsIntrusiveAuth(t *testing.T) {
	a := &App{}
	req, err := a.parseScheduleArgs([]string{"scan", "http://127.0.0.1/", "--allow-intrusive", "--auth-file", "/tmp/a.yaml", "--profile", "standard"})
	if err != nil {
		t.Fatal(err)
	}
	if !req.AllowIntrusive || req.AuthFile != "/tmp/a.yaml" || !req.NonInteractive {
		t.Fatalf("%+v", req)
	}
	for _, argv := range [][]string{
		{"scan", "http://127.0.0.1/", "--header", "X: y"},
		{"scan", "http://127.0.0.1/", "--cookie=x"},
	} {
		if _, err := a.parseScheduleArgs(argv); err == nil || !strings.Contains(err.Error(), "schedules cannot carry") && !strings.Contains(err.Error(), "schedules refuse") {
			t.Fatalf("%v: %v", argv, err)
		}
	}
}

// The run logger masks auth literals: rebuilding it against the run
// redactor (as RunScan does) covers -v output, and restoring the base
// redactor afterwards leaves no literals behind.
func TestRunLoggerMasksLiterals(t *testing.T) {
	const token = "log-literal-token-123456789"
	h := newHarness(t)
	if err := h.app.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer h.app.Close()
	prev := h.app.Redactor
	h.app.Redactor = h.app.Redactor.WithLiterals(token)
	h.app.makeLogger()
	h.app.Log.Info("probe", "auth", token)
	h.app.Redactor = prev
	h.app.makeLogger()
	if strings.Contains(h.stderr.String(), token) {
		t.Fatalf("token in logs: %s", h.stderr.String())
	}
}

// An --auth-file with the wrong mode fails the scan before any request.
func TestScanAuthFileModeRefused(t *testing.T) {
	h := newHarness(t)
	writeIntrusiveConfig(t, h, "127.0.0.1")
	bad := filepath.Join(t.TempDir(), "auth.yaml")
	os.WriteFile(bad, []byte("headers:\n  X: y\n"), 0o644)
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", "http://127.0.0.1:1/", "--auth-file", bad, "--non-interactive", "--out", out)
	if code != ExitUsage || !strings.Contains(h.stderr.String(), "0600") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
}

// scope check explains the intrusive outcome for URL targets.
func TestScopeCheckIntrusive(t *testing.T) {
	h := newHarness(t)
	writeIntrusiveConfig(t, h, "127.0.0.1")
	if code := h.run(t, "scope", "check", "http://127.0.0.1/"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "intrusive: ALLOW with --allow-intrusive") {
		t.Fatalf("%s", h.stdout.String())
	}
	writeIntrusiveConfig(t, h, "")
	if code := h.run(t, "scope", "check", "http://127.0.0.1/"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stdout.String(), "intrusive: SKIP with --allow-intrusive") {
		t.Fatalf("%s", h.stdout.String())
	}
}

// End to end (D6 + acceptance 5.6.4): an authenticated intrusive scan
// finds the reflective parameter, records meta.intrusive and the
// ActionIntrusive row, shows the report banner — and the token appears
// nowhere: not in the DB, reports, audit trail, plan or logs.
func TestScanIntrusiveAuthenticatedNoLeak(t *testing.T) {
	const token = "bearer-D6-no-leak-probe-987654321"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		seen := "no"
		if r.Header.Get("Authorization") == "Bearer "+token {
			seen = "yes"
		}
		fmt.Fprintf(w, `<html><body><a href="/search?q=hi">s</a><a href="/logout">Logout</a><p>auth:%s</p></body></html>`, seen)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Echo the auth header right after the reflection: the probe
		// evidence window covers it, so the reports grep below proves
		// literal-masking rather than absence.
		fmt.Fprintf(w, "<html><body><p>results for %s</p><!-- auth %s --></body></html>", r.URL.Query().Get("q"), r.Header.Get("Authorization"))
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		t.Error("/logout requested")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	h := newHarness(t)
	writeIntrusiveConfig(t, h, "127.0.0.1")
	authPath := filepath.Join(t.TempDir(), "auth.yaml")
	os.WriteFile(authPath, []byte("headers:\n  Authorization: \"Bearer "+token+"\"\n"), 0o600)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", srv.URL+"/", "--allow-intrusive", "--auth-file", authPath,
		"--ack-authorized", "--non-interactive", "--out", out, "--format", "html,json",
		"--engines", "webscan", "--audit-file", auditPath, "-v")
	if code != ExitOK && code != ExitPartial {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	seen := false
	for _, f := range findings {
		if f["rule_id"] == "web.reflected-input" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("no reflected-input in %d findings", len(findings))
	}
	intr, _ := scan["intrusive"].(map[string]any)
	if intr["ran"] != true || intr["probes"] == nil {
		t.Fatalf("meta.intrusive: %v", scan["intrusive"])
	}
	htmlPaths, _ := filepath.Glob(filepath.Join(out, "*", "report.html"))
	if len(htmlPaths) != 1 {
		t.Fatalf("reports: %v", htmlPaths)
	}
	html, _ := os.ReadFile(htmlPaths[0])
	if !strings.Contains(string(html), "Active checks ran") {
		t.Fatal("HTML banner missing")
	}
	foundAction := false
	for _, r := range h.auditRows(t) {
		if r.Action == audit.ActionIntrusive {
			foundAction = true
		}
		if strings.Contains(string(r.Detail), token) {
			t.Fatalf("token in audit row %s", r.Action)
		}
	}
	if !foundAction {
		t.Fatal("no intrusive audit row")
	}
	// The token appears nowhere on disk or on the terminal.
	db, _ := os.ReadFile(filepath.Join(h.home, "scnr.db"))
	reports, _ := readDirFiles(filepath.Dir(htmlPaths[0]))
	auditLog, _ := os.ReadFile(auditPath)
	for name, body := range map[string]string{"db": string(db), "reports": reports, "audit": string(auditLog), "stdout": h.stdout.String(), "stderr": h.stderr.String()} {
		if strings.Contains(body, token) {
			t.Fatalf("token in %s", name)
		}
	}
	// The plan shows counts, never values.
	ws, err := webscan.New()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := safety.LoadAuthFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ws.Plan(context.Background(), domain.Target{Type: domain.TargetURL, Value: srv.URL + "/"}, engine.Options{Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Summary, "authenticated: yes (1 headers, 0 cookies)") {
		t.Fatalf("plan: %q", plan.Summary)
	}
	if strings.Contains(plan.Summary, token) {
		t.Fatalf("token in plan: %q", plan.Summary)
	}
}

func readDirFiles(dir string) (string, error) {
	var b strings.Builder
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		bb, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		b.Write(bb)
	}
	return b.String(), nil
}

// The intrusive refusal is explained on stdout and audited when the flag
// is passed without an intrusive_allow entry.
func TestScanIntrusiveRefusedExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()
	h := newHarness(t)
	writeIntrusiveConfig(t, h, "")
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", srv.URL+"/", "--allow-intrusive", "--ack-authorized", "--non-interactive", "--out", out, "--engines", "webscan")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "active checks skipped") || !strings.Contains(h.stdout.String(), "intrusive_allow") {
		t.Fatalf("%s", h.stdout.String())
	}
	scan, _ := readJSONReport(t, out)
	if intr, _ := scan["intrusive"].(map[string]any); intr["ran"] == true {
		t.Fatalf("intrusive ran: %v", intr)
	}
	found := false
	for _, r := range h.auditRows(t) {
		if r.Action == audit.ActionIntrusive {
			found = true
			if !strings.Contains(string(r.Detail), "intrusive_allow") {
				t.Fatalf("refusal not audited: %s", r.Detail)
			}
		}
	}
	if !found {
		t.Fatal("no intrusive audit row")
	}
}
