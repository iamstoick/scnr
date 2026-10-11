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

	"github.com/iamstoick/scnr/internal/adapter/adaptertest"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/store"
)

func webTarget(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.18.0")
		w.Write([]byte("<html><body>hello</body></html>"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("DB_PASSWORD=TopSecretValue987\n")) })
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ref: refs/heads/main\n")) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fastWeb raises the per-host HTTP rate for URL scans in tests (~300 template
// requests would otherwise take 15s at the 20 rps default). The raise is
// audited like any other limit override.
func fastWeb(t *testing.T, h *harness) []string {
	t.Helper()
	cfg := filepath.Join(h.home, "scnr.yaml")
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true, by: t}\nlimits: {http_rps_per_host: 500}\n"), 0o600)
	h.app.ConfigPath = cfg
	return []string{"--i-understand-rate-limits", "--non-interactive"}
}

func engineStatus(scan map[string]any, name string) (string, string) {
	for _, e := range scan["engines"].([]any) {
		m := e.(map[string]any)
		if m["name"] == name {
			v, _ := m["version"].(string)
			return m["status"].(string), v
		}
	}
	return "", ""
}

// Web scan with all five formats; adapters absent -> skipped, not failed.
func TestScanURLAllFormatsAndMissingAdaptersSkip(t *testing.T) {
	h := newHarness(t)
	srv := webTarget(t)
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, append([]string{"scan", srv.URL, "--format", "html,json,sarif,md,csv", "--out", out, "--ports", "1"}, fastWeb(t, h)...)...)
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	ids := ruleIDs(findings)
	for _, want := range []string{"web.tpl.exposed-env-file", "web.tpl.exposed-git-head", "web.header.csp-missing", "web.server-version-disclosure"} {
		if ids[want] == 0 {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
	if st, _ := engineStatus(scan, "adapter:nmap"); !strings.HasPrefix(st, "skipped") || !strings.Contains(st, "doctor") {
		t.Fatalf("nmap status %q", st)
	}
	if st, _ := engineStatus(scan, "adapter:nuclei"); !strings.HasPrefix(st, "skipped") {
		t.Fatalf("nuclei status %q", st)
	}
	if scan["partial"] != true {
		t.Fatal("missing adapters must mark the scan partial")
	}
	dir := filepath.Join(out, scan["id"].(string))
	for _, f := range []string{"report.sarif", "report.md", "report.csv"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s missing", f)
		}
	}
	sarif, _ := os.ReadFile(filepath.Join(dir, "report.sarif"))
	var log struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string
					Rules []any
				}
			}
			Results []struct {
				RuleID              string
				PartialFingerprints map[string]string
			}
		}
	}
	if err := json.Unmarshal(sarif, &log); err != nil || log.Version != "2.1.0" || len(log.Runs) == 0 {
		t.Fatalf("sarif: %v %+v", err, log)
	}
	total, webRun := 0, -1
	for i, r := range log.Runs {
		total += len(r.Results)
		if r.Tool.Driver.Name == "scnr/webscan" {
			webRun = i
		}
	}
	if webRun < 0 || total != len(findings) || log.Runs[webRun].Results[0].PartialFingerprints["scnr/v1"] == "" {
		t.Fatalf("sarif runs %+v", log.Runs)
	}
	// The .env secret value is nowhere on disk.
	grepTree(t, h.home, "TopSecretValue987")
	grepTree(t, out, "TopSecretValue987")
	if h.run(t, "templates", "list") != 0 || !strings.Contains(h.stdout.String(), "exposed-env-file") || !strings.Contains(h.stdout.String(), "embedded)") {
		t.Fatalf("templates list: %s", h.stdout.String())
	}
}

// Acceptance 2.7 and 2.2: a nuclei run via the adapter uses -ni and the
// exclusion tags (fake binary records argv); nmap version lands in engines.
func TestAdaptersWithFakeBinaries(t *testing.T) {
	h := newHarness(t)
	srv := webTarget(t)
	nucleiFixture := filepath.Join(adaptertest.FixtureDir(t, "nuclei", "3.1.0"), "results.jsonl")
	argvPath := adaptertest.Install(t, "nuclei", "-version", "[INF] Nuclei Engine Version: v3.1.0", adaptertest.CopyToOutBody(nucleiFixture))
	nmapFixture := filepath.Join(adaptertest.FixtureDir(t, "nmap", "7.94"), "scan.xml")
	nmapArgv := adaptertest.Install(t, "nmap", "--version", "Nmap version 7.94 ( https://nmap.org )", adaptertest.CatBody(nmapFixture))
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", srv.URL, "--ack-authorized", "--non-interactive", "--out", out, "--engines", "adapter:nuclei,adapter:nmap", "--ports", "1")
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	argv := adaptertest.Argv(t, argvPath)
	joined := " " + strings.Join(argv, " ") + " "
	for _, want := range []string{" -ni ", " -et dos,fuzz,intrusive,bruteforce,dast ", " -jsonl ", " -silent ", " -u " + srv.URL + "/ "} {
		if !strings.Contains(joined, want) {
			t.Errorf("nuclei argv missing %q: %v", want, argv)
		}
	}
	for _, bad := range []string{"-dast", "-fuzz", "--script"} {
		if strings.Contains(joined, " "+bad+" ") {
			t.Errorf("forbidden %s in argv", bad)
		}
	}
	nm := strings.Join(adaptertest.Argv(t, nmapArgv), " ")
	if strings.Contains(nm, "--script") || strings.Contains(nm, "-sU") || !strings.Contains(nm, "-p 1") || !strings.Contains(nm, "127.0.0.1") {
		t.Fatalf("nmap argv %s", nm)
	}
	scan, findings := readJSONReport(t, out)
	if st, v := engineStatus(scan, "adapter:nuclei"); st != "ok" || v != "3.1.0" {
		t.Fatalf("nuclei engine %q %q", st, v)
	}
	if st, v := engineStatus(scan, "adapter:nmap"); st != "ok" || v != "7.94" {
		t.Fatalf("nmap engine %q %q", st, v)
	}
	ids := ruleIDs(findings)
	if ids["nuclei:CVE-2021-41773"] != 1 || ids["nuclei:git-config"] != 1 || ids["net.open-port"] != 3 {
		t.Fatalf("rule ids %v", ids)
	}
	if h.run(t, "doctor") != 0 || !strings.Contains(h.stdout.String(), "7.94 (adapter enabled)") || !strings.Contains(h.stdout.String(), "3.1.0 (adapter enabled)") {
		t.Fatalf("doctor: %s", h.stdout.String())
	}
}

// Acceptance 2.4: a finding removed between two scans is marked fixed and
// the diff prints 1 fixed / 0 new.
func TestDiffAndFixedLifecycle(t *testing.T) {
	h := newHarness(t)
	osv := fakeOSV(t)
	defer osv.Close()
	h.app.OSVBase = osv.URL
	repo := fixtureRepo(t)
	out := filepath.Join(t.TempDir(), "out")
	if code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out); code != ExitOK {
		t.Fatalf("scan1 %d %s", code, h.stderr.String())
	}
	scan1, f1 := readJSONReport(t, out)
	// Remove the secret, re-scan with --diff latest.
	os.Remove(filepath.Join(repo, "src", "config.py"))
	if code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--diff", "latest"); code != ExitOK {
		t.Fatalf("scan2 %d %s", code, h.stderr.String())
	}
	scan2, f2 := readJSONReport(t, out)
	if len(f2) != len(f1)-1 {
		t.Fatalf("findings %d -> %d", len(f1), len(f2))
	}
	if !strings.Contains(h.stdout.String(), "0 new, 1 fixed") || !strings.Contains(h.stdout.String(), "FIXED") || !strings.Contains(h.stdout.String(), "1 fixed since last scan") {
		t.Fatalf("diff output: %s", h.stdout.String())
	}
	var secretFP string
	for _, f := range f1 {
		if f["rule_id"] == "secret.aws-access-key" {
			secretFP = f["fingerprint"].(string)
		}
	}
	fnd, err := h.store(t).GetFinding(context.Background(), secretFP)
	if err != nil || fnd.Status != domain.StatusFixed {
		t.Fatalf("secret finding status %v %v", fnd, err)
	}
	if h.run(t, "findings", "diff", scan1["id"].(string), scan2["id"].(string)) != 0 || !strings.Contains(h.stdout.String(), "0 new, 1 fixed, ") {
		t.Fatalf("findings diff: %s %s", h.stdout.String(), h.stderr.String())
	}
	if h.run(t, "findings", "diff", scan1["id"].(string), "nope") != ExitUsage {
		t.Fatal("unknown scan in diff must be a usage error")
	}
	if h.run(t, "findings", "list", "--status", "fixed") != 0 || !strings.Contains(h.stdout.String(), "secret.aws-access-key") {
		t.Fatalf("fixed list: %s", h.stdout.String())
	}
}

// Finding 4 (end to end): a nuclei finding is not marked fixed by a later
// scan in which nuclei was skipped (binary absent) or not selected
// (--engines netscan); it is marked fixed once nuclei runs again and no
// longer reports it.
func TestFixedRequiresEngineToHaveRun(t *testing.T) {
	h := newHarness(t)
	srv := webTarget(t)
	fixture := filepath.Join(adaptertest.FixtureDir(t, "nuclei", "3.1.0"), "results.jsonl")
	out := filepath.Join(t.TempDir(), "out")
	base := []string{"scan", srv.URL, "--ack-authorized", "--non-interactive", "--out", out, "--ports", "1"}
	both := append(append([]string{}, base...), "--engines", "adapter:nuclei,netscan")
	adaptertest.Install(t, "nuclei", "-version", "v3.1.0", adaptertest.CopyToOutBody(fixture))
	if code := h.run(t, both...); code != ExitOK {
		t.Fatalf("scan1 %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	_, findings := readJSONReport(t, out)
	var cveFP string
	for _, f := range findings {
		if f["rule_id"] == "nuclei:CVE-2021-41773" {
			cveFP = f["fingerprint"].(string)
		}
	}
	if cveFP == "" {
		t.Fatalf("nuclei finding missing: %v", ruleIDs(findings))
	}
	status := func() domain.Status {
		t.Helper()
		f, err := h.store(t).GetFinding(context.Background(), cveFP)
		if err != nil {
			t.Fatal(err)
		}
		return f.Status
	}
	// Scan 2: nuclei absent -> skipped; the finding stays open.
	adaptertest.Hide(t)
	if code := h.run(t, both...); code != ExitOK {
		t.Fatalf("scan2 %d %s", code, h.stderr.String())
	}
	scan, _ := readJSONReport(t, out)
	if st, _ := engineStatus(scan, "adapter:nuclei"); !strings.HasPrefix(st, "skipped") {
		t.Fatalf("nuclei status %q", st)
	}
	if status() != domain.StatusOpen || strings.Contains(h.stdout.String(), "fixed since last scan") {
		t.Fatalf("finding marked %s although nuclei was skipped: %s", status(), h.stdout.String())
	}
	// Scan 3: nuclei installed but not selected -> still open.
	adaptertest.Install(t, "nuclei", "-version", "v3.1.0", adaptertest.CopyToOutBody(fixture))
	if code := h.run(t, append(append([]string{}, base...), "--engines", "netscan")...); code != ExitOK {
		t.Fatalf("scan3 %d %s", code, h.stderr.String())
	}
	if status() != domain.StatusOpen {
		t.Fatalf("finding marked %s although nuclei was not selected", status())
	}
	// Scan 4: nuclei runs and reports nothing -> fixed.
	adaptertest.Install(t, "nuclei", "-version", "v3.1.0", `: > "$OUT"`)
	if code := h.run(t, both...); code != ExitOK {
		t.Fatalf("scan4 %d %s", code, h.stderr.String())
	}
	if status() != domain.StatusFixed || !strings.Contains(h.stdout.String(), "3 fixed since last scan") {
		t.Fatalf("status %s: %s", status(), h.stdout.String())
	}
}

// Acceptance 2.5 and 2.6: accept requires reason and expiry; fail_on: high
// exits 1 while a high (here KEV-floored) finding is open and 0 once it is
// accepted; an expired acceptance reverts to open with an audit row.
func TestAcceptAndPolicyGate(t *testing.T) {
	h := newHarness(t)
	osv := fakeOSV(t)
	defer osv.Close()
	h.app.OSVBase = osv.URL
	kev, _ := os.ReadFile("../../testdata/vulndb/kev.json")
	epss, _ := os.ReadFile("../../testdata/vulndb/epss.csv")
	feeds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev" {
			w.Write(kev)
		} else {
			w.Write(epss)
		}
	}))
	defer feeds.Close()
	h.app.KEVURL, h.app.EPSSURL = feeds.URL+"/kev", feeds.URL+"/epss.csv"
	if code := h.run(t, "db", "update"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	repo := fixtureRepo(t)
	out := filepath.Join(t.TempDir(), "out")
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(policy, []byte("fail_on: high\nfail_on_kev: true\n"), 0o600)
	badPolicy := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(badPolicy, []byte("fail_on: urgent\n"), 0o600)
	if code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--policy", badPolicy); code != ExitUsage {
		t.Fatalf("bad policy exit %d", code)
	}

	code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--policy", policy)
	if code != ExitPolicy || !strings.Contains(h.stdout.String(), "POLICY FAIL: fail_on high") || !strings.Contains(h.stdout.String(), "fail_on_kev") {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	var kevFP string
	for _, f := range findings {
		if f["kev"] == true {
			kevFP = f["fingerprint"].(string)
			if f["risk"].(float64) < 90 {
				t.Fatalf("KEV floor not applied: %v", f["risk"])
			}
		}
	}
	if kevFP == "" {
		t.Fatal("expected a KEV finding (lodash CVE-2020-8203)")
	}
	if h.run(t, "policy", "check", scan["id"].(string), "--policy", policy) != ExitPolicy {
		t.Fatalf("policy check should fail: %s", h.stdout.String())
	}

	// accept: reason and expiry are mandatory, expiry capped.
	if h.run(t, "accept", kevFP, "--expires", "30d") != ExitUsage {
		t.Fatal("accept without reason accepted")
	}
	if h.run(t, "accept", kevFP, "--reason", "r") != ExitUsage {
		t.Fatal("accept without expiry accepted")
	}
	if h.run(t, "accept", kevFP, "--reason", "r", "--expires", "400d") != ExitUsage {
		t.Fatal("accept beyond 365d accepted")
	}
	if h.run(t, "accept", strings.Repeat("0", 64), "--reason", "r", "--expires", "1d") != ExitUsage {
		t.Fatal("accept of unknown fingerprint succeeded")
	}
	if code := h.run(t, "accept", kevFP, "--reason", "lodash is not reachable from user input", "--expires", "30d"); code != 0 {
		t.Fatalf("accept: %d %s", code, h.stderr.String())
	}
	if h.run(t, "accept", "list") != 0 || !strings.Contains(h.stdout.String(), kevFP[:16]) || !strings.Contains(h.stdout.String(), "active") {
		t.Fatalf("accept list: %s", h.stdout.String())
	}
	// policy check on the same scan now passes (accepted findings are not open).
	if code := h.run(t, "policy", "check", "latest", "--policy", policy); code != ExitOK || !strings.Contains(h.stdout.String(), "POLICY PASS") {
		t.Fatalf("policy check after accept: %d %s", code, h.stdout.String())
	}
	// Re-scan with the policy: exit 0, finding reported as accepted.
	if code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--policy", policy); code != ExitOK {
		t.Fatalf("scan after accept exit %d: %s", code, h.stdout.String())
	}
	_, findings = readJSONReport(t, out)
	for _, f := range findings {
		if f["fingerprint"] == kevFP && f["status"] != "accepted" {
			t.Fatalf("status %v", f["status"])
		}
	}
	// Markdown report lists it under accepted.
	// (SARIF carries a suppression; covered in report tests.)

	// Expiry: force the acceptance to expire, re-scan -> open again + audit row.
	s := h.store(t)
	sups, _ := s.ListSuppressions(context.Background(), false, 10)
	if len(sups) != 1 {
		t.Fatalf("suppressions %d", len(sups))
	}
	// There is deliberately no API to edit expiry; emulate time passing by
	// revoking and re-adding with a 1s expiry, then waiting.
	if h.run(t, "accept", "revoke", sups[0].ID[:12]) != 0 {
		t.Fatal(h.stderr.String())
	}
	if f, _ := s.GetFinding(context.Background(), kevFP); f.Status != domain.StatusOpen {
		t.Fatalf("revoke did not reopen: %s", f.Status)
	}
	if _, _, err := s.AddSuppression(context.Background(), store.Suppression{Fingerprint: kevFP, Reason: "short", CreatedBy: "t", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	time.Sleep(1100 * time.Millisecond)
	if code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--policy", policy); code != ExitPolicy || !strings.Contains(h.stdout.String(), "1 acceptance(s) expired") {
		t.Fatalf("expired acceptance: exit %d %s", code, h.stdout.String())
	}
	if f, _ := h.store(t).GetFinding(context.Background(), kevFP); f.Status != domain.StatusOpen {
		t.Fatalf("expired acceptance status %s", f.Status)
	}
	actions := map[string]int{}
	for _, r := range h.auditRows(t) {
		actions[r.Action]++
	}
	if actions["accept"] != 1 || actions["accept_revoke"] != 1 || actions["accept_expired"] != 1 || actions["policy_check"] != 2 {
		t.Fatalf("audit actions %v", actions)
	}
	if h.run(t, "accept", "list", "--all") != 0 || !strings.Contains(h.stdout.String(), "revoked") || !strings.Contains(h.stdout.String(), "expired") {
		t.Fatalf("accept list --all: %s", h.stdout.String())
	}
}

func TestBaselineSuppresses(t *testing.T) {
	h := newHarness(t)
	srv := webTarget(t)
	out := filepath.Join(t.TempDir(), "out")
	fast := fastWeb(t, h)
	if code := h.run(t, append([]string{"scan", srv.URL, "--out", out, "--engines", "webscan"}, fast...)...); code != ExitOK {
		t.Fatalf("scan %d %s", code, h.stderr.String())
	}
	if h.run(t, "baseline", "create", "--from", "latest") != 0 {
		t.Fatal(h.stderr.String())
	}
	baseline := filepath.Join(t.TempDir(), "baseline.yaml")
	os.WriteFile(baseline, h.stdout.Bytes(), 0o600)
	if !strings.Contains(h.stdout.String(), "web.tpl.exposed-env-file") {
		t.Fatalf("baseline: %s", h.stdout.String())
	}
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(policy, []byte("fail_on: low\n"), 0o600)
	if code := h.run(t, append([]string{"scan", srv.URL, "--out", out, "--engines", "webscan", "--policy", policy}, fast...)...); code != ExitPolicy {
		t.Fatalf("without baseline exit %d", code)
	}
	if code := h.run(t, append([]string{"scan", srv.URL, "--out", out, "--engines", "webscan", "--policy", policy, "--baseline", baseline}, fast...)...); code != ExitOK {
		t.Fatalf("with baseline exit %d: %s", code, h.stdout.String())
	}
	_, findings := readJSONReport(t, out)
	for _, f := range findings {
		if f["status"] != "suppressed" {
			t.Fatalf("finding not suppressed: %v", f["rule_id"])
		}
	}
	if len(findings) == 0 {
		t.Fatal("suppressed findings must still be reported")
	}
	// Scanning again without the baseline reopens them.
	if code := h.run(t, append([]string{"scan", srv.URL, "--out", out, "--engines", "webscan"}, fast...)...); code != ExitOK {
		t.Fatal(code)
	}
	_, findings = readJSONReport(t, out)
	if findings[0]["status"] != "open" {
		t.Fatalf("status %v", findings[0]["status"])
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(bad, []byte("version: 1\nfingerprints: [zzz]\n"), 0o600)
	if code := h.run(t, append([]string{"scan", srv.URL, "--out", out, "--baseline", bad}, fast...)...); code != ExitUsage {
		t.Fatalf("bad baseline exit %d", code)
	}
}

func TestTemplatesValidateAndUserDir(t *testing.T) {
	h := newHarness(t)
	fast := fastWeb(t, h)
	dir := t.TempDir()
	good := "id: my-marker\ninfo: {title: Marker, severity: info, what: w, why: y, fix: f}\nsafety: safe\nhttp:\n  - method: GET\n    path: [\"/marker.txt\"]\n    matchers:\n      - {type: status, status: [200]}\n      - {type: word, words: [MARKER]}\n"
	os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(good), 0o600)
	if code := h.run(t, "templates", "validate", dir); code != 0 || !strings.Contains(h.stdout.String(), "OK    good.yaml") {
		t.Fatalf("%d %s", code, h.stdout.String())
	}
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(strings.Replace(good, "safety: safe", "safety: nuke", 1)), 0o600)
	if code := h.run(t, "templates", "validate", dir); code != ExitPolicy || !strings.Contains(h.stdout.String(), "ERROR") {
		t.Fatalf("%d %s", code, h.stdout.String())
	}
	srv := webTarget(t)
	out := filepath.Join(t.TempDir(), "out")
	// A broken user template directory refuses to scan.
	if code := h.run(t, append([]string{"scan", srv.URL, "--out", out, "--templates", dir, "--engines", "webscan"}, fast...)...); code != ExitUsage {
		t.Fatalf("bad templates dir exit %d", code)
	}
	os.Remove(filepath.Join(dir, "bad.yaml"))
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/marker.txt" {
			w.Write([]byte("MARKER"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv2.Close()
	if code := h.run(t, append([]string{"scan", srv2.URL, "--out", out, "--templates", dir, "--engines", "webscan"}, fast...)...); code != ExitOK {
		t.Fatalf("exit %d %s", code, h.stderr.String())
	}
	_, findings := readJSONReport(t, out)
	if ruleIDs(findings)["web.tpl.my-marker"] != 1 {
		t.Fatalf("user template did not fire: %v", ruleIDs(findings))
	}
}
