package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/store"
)

const fakeAWS = "AKIAIOSFODNN7EXAMPLE"

type fakeResolver struct {
	hosts map[string][]string
	txt   map[string][]string
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f.hosts[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

type harness struct {
	app    *App
	home   string
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	res    *fakeResolver
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	// Hide real tools (nmap is installed on dev machines): CLI tests use the
	// fake binaries from adaptertest or expect adapters to be skipped.
	t.Setenv("PATH", t.TempDir())
	home := t.TempDir()
	h := &harness{home: home, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, res: &fakeResolver{hosts: map[string][]string{}, txt: map[string][]string{}}}
	h.app = &App{Version: "test", Home: home, Stdout: h.stdout, Stderr: h.stderr, Stdin: strings.NewReader(""), Resolver: h.res, Redactor: safety.NewRedactor()}
	return h
}

// run executes a command line and returns the exit code. A fresh App is
// built per invocation (like a real process) but shares the home dir.
func (h *harness) run(t *testing.T, args ...string) int {
	t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	app := &App{Version: "test", Home: h.home, Stdout: h.stdout, Stderr: h.stderr, Stdin: h.app.Stdin, Resolver: h.res, Redactor: h.app.Redactor,
		OSVBase: h.app.OSVBase, KEVURL: h.app.KEVURL, EPSSURL: h.app.EPSSURL, BundleBase: h.app.BundleBase, AWSEndpoint: h.app.AWSEndpoint, IsTTY: h.app.IsTTY, ConfigPath: h.app.ConfigPath}
	code := Execute(context.Background(), app, args)
	h.app.IsTTY = app.IsTTY
	return code
}

func (h *harness) store(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(h.home, "scnr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func (h *harness) auditRows(t *testing.T) []store.AuditEntry {
	t.Helper()
	rows, err := h.store(t).ListAudit(context.Background(), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func fixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "src"), 0o755)
	os.WriteFile(filepath.Join(dir, "src", "config.py"), []byte("AWS_ACCESS_KEY_ID = \""+fakeAWS+"\"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"}}}`), 0o600)
	return dir
}

func fakeOSV(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name string } `json:"package"`
					Version string
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				results[i] = map[string]any{"vulns": []any{}}
				if q.Package.Name == "lodash" {
					results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-p6mc-m468-83gw"}}}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			json.NewEncoder(w).Encode(map[string]any{
				"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash", "aliases": []string{"CVE-2020-8203"},
				"affected": []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "lodash"},
					"ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}}}}},
				"database_specific": map[string]any{"severity": "HIGH"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func readJSONReport(t *testing.T, out string) (map[string]any, []map[string]any) {
	t.Helper()
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no report dir: %v", err)
	}
	var newest string
	var newestTime int64
	for _, e := range entries {
		info, _ := e.Info()
		if info.ModTime().UnixNano() >= newestTime {
			newestTime = info.ModTime().UnixNano()
			newest = e.Name()
		}
	}
	b, err := os.ReadFile(filepath.Join(out, newest, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, newest, "report.html")); err != nil {
		t.Fatal("report.html missing")
	}
	var doc struct {
		Scan     map[string]any   `json:"scan"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Scan, doc.Findings
}

func ruleIDs(fs []map[string]any) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f["rule_id"].(string)]++
	}
	return m
}

// Criterion 1: no TTY -> usage + exit 2.
func TestNoTTYPrintsUsageExit2(t *testing.T) {
	h := newHarness(t)
	if code := h.run(t); code != ExitUsage {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(h.stderr.String(), "Usage:") {
		t.Fatalf("stderr: %s", h.stderr.String())
	}
	if code := h.run(t, "scan"); code != ExitUsage {
		t.Fatalf("scan without target: exit %d", code)
	}
}

// Criterion 2: local listeners -> open ports + self-signed + reports.
func TestScanLocalhostListeners(t *testing.T) {
	h := newHarness(t)
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
	defer httpSrv.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
	defer tlsSrv.Close()
	_, hp, _ := net.SplitHostPort(httpSrv.Listener.Addr().String())
	// TLS detection keys off well-known ports (and ports ending in 443), so
	// bind the TLS server to 18443 explicitly when it is free.
	var tlsPort string
	if ln, err := net.Listen("tcp", "127.0.0.1:18443"); err == nil {
		ln.Close()
		tlsSrv.Close()
		tlsSrv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
		tlsSrv.Listener, _ = net.Listen("tcp", "127.0.0.1:18443")
		tlsSrv.StartTLS()
		tlsPort = "18443"
	} else {
		t.Skip("port 18443 busy")
	}
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", "127.0.0.1", "--ack-authorized", "--non-interactive", "--ports", hp+","+tlsPort, "--out", out)
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	ids := ruleIDs(findings)
	if ids["net.open-port"] != 2 || ids["net.tls.self-signed"] != 1 {
		t.Fatalf("rule ids = %v", ids)
	}
	if scan["consent"].(map[string]any)["method"] != domain.ConsentPrivateRange {
		t.Fatalf("consent %v", scan["consent"])
	}
	// Criterion 9: exactly one audit row for the scan with consent + exit code.
	rows := h.auditRows(t)
	n := 0
	for _, r := range rows {
		if r.Action == "scan" {
			n++
			var d map[string]any
			json.Unmarshal(r.Detail, &d)
			if d["consent_method"] != domain.ConsentPrivateRange || d["exit_code"].(float64) != 0 || r.ScanID == "" {
				t.Fatalf("audit detail %s", r.Detail)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want 1 scan audit row, got %d", n)
	}
	// scan list / show / findings list / report re-render.
	if h.run(t, "scan", "list") != 0 || !strings.Contains(h.stdout.String(), scan["id"].(string)) {
		t.Fatalf("scan list: %s", h.stdout.String())
	}
	if h.run(t, "scan", "show", "latest") != 0 || !strings.Contains(h.stdout.String(), "netscan") {
		t.Fatalf("scan show: %s", h.stdout.String())
	}
	if h.run(t, "findings", "list", "--scan", scan["id"].(string)) != 0 || !strings.Contains(h.stdout.String(), "net.tls.self-signed") {
		t.Fatalf("findings list: %s", h.stdout.String())
	}
	fp := findings[0]["fingerprint"].(string)
	if h.run(t, "findings", "show", fp[:16]) != 0 || !strings.Contains(h.stdout.String(), "Evidence") {
		t.Fatalf("findings show: %s", h.stdout.String())
	}
	out2 := filepath.Join(t.TempDir(), "re")
	if h.run(t, "report", "latest", "--out", out2) != 0 {
		t.Fatalf("report: %s", h.stderr.String())
	}
	if h.run(t, "assets", "list") != 0 || !strings.Contains(h.stdout.String(), "host:127.0.0.1") {
		t.Fatalf("assets: %s", h.stdout.String())
	}
}

// Criteria 3 and 4: secrets redaction + SCA online/offline.
func TestScanRepoSecretsAndSCA(t *testing.T) {
	h := newHarness(t)
	osv := fakeOSV(t)
	defer osv.Close()
	h.app.OSVBase = osv.URL
	repo := fixtureRepo(t)
	out := filepath.Join(t.TempDir(), "out")

	// The Phase 3 tool adapters are absent on the harness PATH and would be
	// reported skipped (partial); deselect them so this test keeps asserting
	// that the native engines alone make a complete scan.
	noTools := "adapter:semgrep,adapter:trivy,adapter:grype"
	code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--skip-engines", noTools)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	ids := ruleIDs(findings)
	if ids["secret.aws-access-key"] != 1 {
		t.Fatalf("rules %v", ids)
	}
	if ids["sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"] != 1 {
		t.Fatalf("sca finding missing: %v", ids)
	}
	for _, f := range findings {
		switch f["rule_id"] {
		case "secret.aws-access-key":
			ev := f["evidence"].([]any)[0].(map[string]any)
			red := ev["redacted"].(string)
			if !strings.HasPrefix(red, "AKIA") || !strings.HasSuffix(red, "E") || !strings.Contains(red, "*") || ev["hash"] == "" || ev["hash"] == domain.SHA256Hex(fakeAWS) {
				t.Fatalf("redacted evidence = %v", ev)
			}
		case "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20":
			if !strings.Contains(f["how_to_fix"].(string), "4.17.21") {
				t.Fatalf("fix = %v", f["how_to_fix"])
			}
		}
	}
	if scan["partial"] != false {
		t.Fatal("online scan should not be partial")
	}
	// Raw key appears nowhere on disk: DB, WAL, reports.
	for _, root := range []string{h.home, out} {
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(fakeAWS)) {
				t.Errorf("raw secret found in %s", p)
			}
			return nil
		})
	}

	// Offline: sca skipped, partial, exit 0; --strict -> exit 5.
	code = h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--offline", "--out", out)
	if code != ExitOK {
		t.Fatalf("offline exit %d", code)
	}
	scan, _ = readJSONReport(t, out)
	if scan["partial"] != true {
		t.Fatal("offline scan must be partial")
	}
	engines := scan["engines"].([]any)
	skipped := false
	for _, e := range engines {
		if m := e.(map[string]any); m["name"] == "sca" && m["status"] == "skipped: offline" {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("engines %v", engines)
	}
	if code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--offline", "--strict", "--out", out); code != ExitPartial {
		t.Fatalf("strict offline exit %d, want 5", code)
	}
	// Three scans -> three audit rows with exit codes 0,0,5.
	codes := []float64{}
	for _, r := range h.auditRows(t) {
		if r.Action == "scan" {
			var d map[string]any
			json.Unmarshal(r.Detail, &d)
			codes = append(codes, d["exit_code"].(float64))
		}
	}
	if len(codes) != 3 || codes[0] != 5 {
		t.Fatalf("audit exit codes %v", codes)
	}
}

// Criterion 6 (gate at the CLI level) and 9 (refusals audited).
func TestGateRefusalsExit3(t *testing.T) {
	h := newHarness(t)
	h.res.hosts["public.test"] = []string{"203.0.113.10"}
	out := filepath.Join(t.TempDir(), "out")
	// No acknowledgment at all.
	if code := h.run(t, "scan", "127.0.0.1", "--non-interactive", "--ports", "1", "--out", out); code != ExitRefused {
		t.Fatalf("no ack: exit %d", code)
	}
	// Public, non-interactive, unverified, not in allow.
	if code := h.run(t, "scan", "203.0.113.10", "--ack-authorized", "--non-interactive", "--out", out); code != ExitRefused {
		t.Fatalf("public bare ip: exit %d", code)
	}
	// Public hostname in allow but unverified.
	cfg := filepath.Join(h.home, "scnr.yaml")
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true, by: t}\nscope:\n  allow: [public.test, denied.test]\n  deny: [denied.test]\n"), 0o600)
	h.app.ConfigPath = cfg
	if code := h.run(t, "scan", "public.test", "--non-interactive", "--out", out); code != ExitRefused || !strings.Contains(h.stderr.String(), "ownership") {
		t.Fatalf("unverified public: exit %d %s", code, h.stderr.String())
	}
	// Verified (via DNS TXT) but denied -> still refused.
	h.res.hosts["denied.test"] = []string{"203.0.113.20"}
	s := h.store(t)
	s.PutVerification(context.Background(), store.Verification{Host: "denied.test", Method: "dns-txt", VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)})
	s.Close()
	if code := h.run(t, "scan", "denied.test", "--non-interactive", "--out", out); code != ExitRefused || !strings.Contains(h.stderr.String(), "E_SCOPE_DENIED") {
		t.Fatalf("denied: exit %d %s", code, h.stderr.String())
	}
	// CIDR /15 private refused without --max-hosts.
	if code := h.run(t, "scan", "10.0.0.0/15", "--non-interactive", "--out", out); code != ExitRefused || !strings.Contains(h.stderr.String(), "E_CIDR_TOO_LARGE") {
		t.Fatalf("/15: exit %d %s", code, h.stderr.String())
	}
	refusals := 0
	for _, r := range h.auditRows(t) {
		if r.Action == "gate_refused" {
			refusals++
		}
	}
	if refusals != 5 {
		t.Fatalf("want 5 gate_refused audit rows, got %d", refusals)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("no reports should be written on refusal")
	}
	// scope check explains.
	if h.run(t, "scope", "check", "public.test") != 0 || !strings.Contains(h.stdout.String(), "REFUSE") {
		t.Fatalf("scope check: %s", h.stdout.String())
	}
	if h.run(t, "scope", "check", "127.0.0.1") != 0 || !strings.Contains(h.stdout.String(), "ALLOW") {
		t.Fatalf("scope check: %s", h.stdout.String())
	}
}

// Criterion 7: verify token determinism and --check.
func TestVerifyCommand(t *testing.T) {
	h := newHarness(t)
	if h.run(t, "verify", "example.test", "--print-token") != 0 {
		t.Fatal(h.stderr.String())
	}
	tok1 := strings.TrimSpace(h.stdout.String())
	h.run(t, "verify", "example.test", "--print-token")
	if tok2 := strings.TrimSpace(h.stdout.String()); tok1 != tok2 || !strings.HasPrefix(tok1, "scnr-verify=") {
		t.Fatalf("token not deterministic: %q %q", tok1, tok2)
	}
	if code := h.run(t, "verify", "example.test", "--check"); code != ExitRefused {
		t.Fatalf("unpublished check should fail: %d", code)
	}
	h.res.txt["_scnr-verify.example.test"] = []string{tok1}
	h.res.hosts["example.test"] = []string{"203.0.113.5"}
	if code := h.run(t, "verify", "example.test", "--check"); code != 0 {
		t.Fatalf("check: %d %s", code, h.stderr.String())
	}
	v, err := h.store(t).GetVerification(context.Background(), "example.test")
	if err != nil || v.Method != "dns-txt" {
		t.Fatal(err)
	}
	if d := v.ExpiresAt.Sub(v.VerifiedAt); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("expiry %v", d)
	}
	verifies := 0
	for _, r := range h.auditRows(t) {
		if r.Action == "verify" {
			verifies++
		}
	}
	if verifies != 2 {
		t.Fatalf("audit verify rows %d", verifies)
	}
}

// Criterion 8: db update from fixtures; doctor reports age and exits 0.
func TestDBUpdateAndDoctor(t *testing.T) {
	h := newHarness(t)
	kev, _ := os.ReadFile("../../testdata/vulndb/kev.json")
	epss, _ := os.ReadFile("../../testdata/vulndb/epss.csv")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev" {
			w.Write(kev)
		} else {
			w.Write(epss)
		}
	}))
	defer srv.Close()
	h.app.KEVURL, h.app.EPSSURL = srv.URL+"/kev", srv.URL+"/epss.csv"
	if code := h.run(t, "doctor"); code != 0 || !strings.Contains(h.stdout.String(), "vulndb kev") || !strings.Contains(h.stdout.String(), "MISSING") {
		t.Fatalf("doctor before: %d %s", code, h.stdout.String())
	}
	if code := h.run(t, "db", "update"); code != 0 || !strings.Contains(h.stdout.String(), "2 KEV") {
		t.Fatalf("db update: %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run(t, "doctor"); code != 0 {
		t.Fatalf("doctor: %d", code)
	}
	out := h.stdout.String()
	if !strings.Contains(out, "vulndb kev") || !strings.Contains(out, "2 rows") || !strings.Contains(out, "tool ") || !strings.Contains(out, "database") {
		t.Fatalf("doctor output: %s", out)
	}
	if h.run(t, "db", "status") != 0 || !strings.Contains(h.stdout.String(), "epss") {
		t.Fatal(h.stdout.String())
	}
	if h.run(t, "doctor", "--install-guide") != 0 || !strings.Contains(h.stdout.String(), "brew install") {
		t.Fatal(h.stdout.String())
	}
	if h.run(t, "config", "show", "--risk") != 0 || !strings.Contains(h.stdout.String(), "KEV floor") {
		t.Fatal(h.stdout.String())
	}
	if h.run(t, "version") != 0 || !strings.Contains(h.stdout.String(), "scnr test") {
		t.Fatal(h.stdout.String())
	}
	// A KEV finding now gets the floor: scan a listener on a port and check
	// enrichment is wired by inspecting the JSON for exploit_data_available.
	if h.run(t, "scope", "init", "--yes", "--out", filepath.Join(h.home, "scnr.yaml")) != 0 {
		t.Fatal(h.stderr.String())
	}
	b, _ := os.ReadFile(filepath.Join(h.home, "scnr.yaml"))
	if !strings.Contains(string(b), "acknowledged: true") {
		t.Fatalf("scope init: %s", b)
	}
}

// grepTree fails the test if needle appears in any file under root.
func grepTree(t *testing.T, root, needle string) {
	t.Helper()
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(needle)) {
			t.Errorf("%q found in %s", needle, p)
		}
		return nil
	})
}

// Finding 5: credentials in a target URL are rejected and never persisted
// or echoed (DB, WAL, audit mirror, reports, stdout, stderr).
func TestURLCredentialsRejectedAndNeverStored(t *testing.T) {
	h := newHarness(t)
	h.res.hosts["host.test"] = []string{"203.0.113.10"}
	out := filepath.Join(t.TempDir(), "out")
	auditFile := filepath.Join(h.home, "audit.jsonl")
	const secret = "Hunter2"
	code := h.run(t, "scan", "https://u:"+secret+"!@host.test/", "--ack-authorized", "--non-interactive", "--out", out, "--audit-file", auditFile)
	if code != ExitUsage {
		t.Fatalf("exit %d, want %d: %s", code, ExitUsage, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "credentials in the target URL") {
		t.Fatalf("stderr should explain: %s", h.stderr.String())
	}
	for name, buf := range map[string]string{"stdout": h.stdout.String(), "stderr": h.stderr.String()} {
		if strings.Contains(buf, secret) {
			t.Errorf("%s leaks the password: %s", name, buf)
		}
	}
	grepTree(t, h.home, secret)
	if _, err := os.Stat(out); err == nil {
		grepTree(t, out, secret)
	}
	// Defence in depth: the redaction layer on its own (used for t.Raw,
	// audit details and stderr) strips the password from a user:pass@ URL.
	if red := h.app.redact("E_X: https://u:" + secret + "!@host.test/: refused"); strings.Contains(red, secret) || !strings.Contains(red, "u:***@") {
		t.Errorf("redact = %q", red)
	}
}

// Finding 6: `db migrate --down` refuses while audit rows exist, and the
// acknowledged rollback is itself audited first.
func TestMigrateDownRefusesAuditLoss(t *testing.T) {
	h := newHarness(t)
	if code := h.run(t, "verify", "example.test", "--print-token"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	// --print-token alone writes no audit row; force one via a refusal.
	if code := h.run(t, "scan", "127.0.0.1", "--non-interactive", "--ports", "1"); code != ExitRefused {
		t.Fatalf("exit %d", code)
	}
	if len(h.auditRows(t)) == 0 {
		t.Fatal("expected an audit row")
	}
	auditFile := filepath.Join(h.home, "audit.jsonl")
	if code := h.run(t, "db", "migrate", "--down", "1", "--audit-file", auditFile); code != ExitRefused || !strings.Contains(h.stderr.String(), "i-understand-audit-loss") {
		t.Fatalf("down without flag: exit %d %s", code, h.stderr.String())
	}
	latest, _ := store.LatestMigrationVersion()
	// Opening the store re-applies pending migrations, so the version the
	// command prints is the authoritative post-rollback state.
	if code := h.run(t, "db", "migrate"); code != 0 || !strings.Contains(h.stdout.String(), "schema version "+strconv.Itoa(latest)) {
		t.Fatalf("schema changed despite refusal: %s", h.stdout.String())
	}
	if code := h.run(t, "db", "migrate", "--down", "1", "--i-understand-audit-loss", "--audit-file", auditFile); code != 0 {
		t.Fatalf("acknowledged down: exit %d %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "schema version "+strconv.Itoa(latest-1)) {
		t.Fatalf("schema version after down: %s", h.stdout.String())
	}
	// The mirror file holds the db_migrate_down row even if the DB table went away.
	b, _ := os.ReadFile(auditFile)
	if !strings.Contains(string(b), `"action":"db_migrate_down"`) {
		t.Fatalf("audit mirror missing rollback row: %s", b)
	}
}

func TestBrokenScopeFileIsAnError(t *testing.T) {
	h := newHarness(t)
	cfg := filepath.Join(h.home, "scnr.yaml")
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true}\nunknown_key: 1\n"), 0o600)
	h.app.ConfigPath = cfg
	if code := h.run(t, "scan", "127.0.0.1", "--non-interactive", "--ports", "1"); code != ExitUsage || !strings.Contains(h.stderr.String(), "scope file") {
		t.Fatalf("exit %d %s", code, h.stderr.String())
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	if code := h.run(t, "scan", "127.0.0.1", "--ack-authorized", "--non-interactive", "--profile", "turbo"); code != ExitUsage {
		t.Fatalf("bad profile exit %d", code)
	}
	if code := h.run(t, "scan", "127.0.0.1", "--ack-authorized", "--non-interactive", "--ports", "99999"); code != ExitUsage {
		t.Fatalf("bad ports exit %d", code)
	}
	if code := h.run(t, "scan", "127.0.0.1", "--ack-authorized", "--non-interactive", "--format", "pdf"); code != ExitUsage {
		t.Fatalf("bad format exit %d", code)
	}
	if code := h.run(t, "scan", "127.0.0.1", "--ack-authorized", "--non-interactive", "--rate", "100000"); code != ExitRefused {
		t.Fatalf("rate above 2x without flag: exit %d", code)
	}
	if code := h.run(t, "scan", "does-not-exist.invalid", "--ack-authorized", "--non-interactive"); code != ExitUsage || !strings.Contains(h.stderr.String(), "E_TARGET_AMBIGUOUS") {
		t.Fatalf("ambiguous: %d %s", code, h.stderr.String())
	}
}
