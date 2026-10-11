package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/gerald/scnr/internal/adapter/adaptertest"
	"github.com/gerald/scnr/internal/audit"
	"github.com/gerald/scnr/internal/domain"
	cloudaws "github.com/gerald/scnr/internal/engine/cloud/aws"
	"github.com/gerald/scnr/internal/engine/cloud/aws/awstest"
	"github.com/gerald/scnr/internal/store"
)

// Fake credential material, built by concatenation so no scanner (ours or
// gitleaks) sees a literal key in the source. The values must appear in
// no output of a scan (B8).
var (
	fakeAWSKey    = "AKIA" + "FAKE" + "KEYFAKEKEY99"
	fakeAWSSecret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
	fakeAWSToken  = "FQoGZXIvYXdzE" + "FAKESESSIONTOKENVALUE"
)

// cloudEnv points the credential chain at fake static env keys with the
// shared-config files isolated from the developer's ~/.aws.
func cloudEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", fakeAWSKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", fakeAWSSecret)
	t.Setenv("AWS_SESSION_TOKEN", fakeAWSToken)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ROLE_ARN", "")
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
}

func writeCloudConfig(t *testing.T, h *harness, accounts string) {
	t.Helper()
	cfg := filepath.Join(h.home, "scnr.yaml")
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true, by: t}\nscope:\n  allow: []\n  deny: []\ncloud:\n  aws:\n    accounts: ["+accounts+"]\n    regions: [us-east-1]\n"), 0o600)
	h.app.ConfigPath = cfg
}

func scanAudit(t *testing.T, h *harness) map[string]any {
	t.Helper()
	for _, r := range h.auditRows(t) {
		if r.Action == audit.ActionScan {
			var d map[string]any
			json.Unmarshal(r.Detail, &d)
			return d
		}
	}
	t.Fatal("no scan audit row")
	return nil
}

// Acceptance 4b.1, 4b.2, 4b.4, 4b.5: allow-listed account scans with
// findings for the fixture rules on asset aws:<account>; the same without
// the allowlist exits 3 non-interactively and prompts for the account id
// interactively; prowler dedupes onto native rules; doctor reports the
// cloud state; config show prints the IAM policy.
func TestCloudScanEndToEnd(t *testing.T) {
	cloudEnv(t)
	h := newHarness(t)
	srv := awstest.New(t, awstest.Fixture{})
	h.app.AWSEndpoint = srv.URL
	writeCloudConfig(t, h, awstest.DefaultAccount)
	out := filepath.Join(t.TempDir(), "out")
	if code := h.run(t, "scan", "aws://", "--ack-authorized", "--non-interactive", "--out", out, "--engines", cloudaws.Name); code != ExitOK {
		t.Fatalf("scan: %d %s", code, h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	if st, _ := engineStatus(scan, cloudaws.Name); st != "ok" {
		t.Fatalf("cloud-aws status %q", st)
	}
	if m := scan["consent"].(map[string]any)["method"]; m != domain.ConsentCloudAllowlist {
		t.Fatalf("consent method %v", m)
	}
	rules := map[string]bool{}
	for _, f := range findings {
		rules[f["rule_id"].(string)] = true
		if f["asset_key"] != "aws:"+awstest.DefaultAccount || !strings.HasPrefix(f["location"].(string), "arn:aws:") {
			t.Errorf("finding %v %v", f["asset_key"], f["location"])
		}
	}
	if len(rules) < 23 {
		t.Fatalf("expected findings for the fixture rules, got %d rules: %v", len(rules), rules)
	}
	targets := scan["targets"].([]any)[0].(map[string]any)
	if targets["value"] != "aws://"+awstest.DefaultAccount {
		t.Fatalf("target value %v", targets["value"])
	}
	detail := scanAudit(t, h)
	id, _ := detail["cloud_identity"].(map[string]any)
	if id["source"] != "env" || !strings.HasPrefix(id["principal"].(string), "arn:aws:iam::") || id["account"] != awstest.DefaultAccount {
		t.Fatalf("audit cloud_identity: %v", id)
	}
	raw, _ := json.Marshal(detail)
	for _, secret := range []string{fakeAWSKey, fakeAWSSecret, fakeAWSToken} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("audit detail carries key material")
		}
	}

	// 4b.2: not allow-listed, non-interactive -> exit 3, audited.
	writeCloudConfig(t, h, "999999999999")
	if code := h.run(t, "scan", "aws://", "--ack-authorized", "--non-interactive", "--out", out, "--engines", cloudaws.Name); code != ExitRefused || !strings.Contains(h.stderr.String(), "E_CLOUD_ACCOUNT_NOT_ALLOWED") {
		t.Fatalf("mismatch: %d %s", code, h.stderr.String())
	}
	refused := false
	for _, r := range h.auditRows(t) {
		if r.Action == audit.ActionGateRefused && strings.Contains(string(r.Detail), "E_CLOUD_ACCOUNT_NOT_ALLOWED") {
			refused = true
		}
	}
	if !refused {
		t.Fatal("no gate_refused audit row")
	}
	// Interactive: the prompt names the account and the typed id is accepted.
	h.app.IsTTY = true
	h.app.Stdin = strings.NewReader(awstest.DefaultAccount + "\n")
	if code := h.run(t, "scan", "aws://", "--ack-authorized", "--out", out, "--engines", cloudaws.Name); code != ExitOK {
		t.Fatalf("interactive: %d %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "Type the account ID ("+awstest.DefaultAccount+")") || !strings.Contains(h.stdout.String(), "credentials from env") {
		t.Fatalf("prompt: %s", h.stdout.String())
	}
	scan, _ = readJSONReport(t, out)
	if m := scan["consent"].(map[string]any)["method"]; m != domain.ConsentInteractive {
		t.Fatalf("interactive consent method %v", m)
	}
	// Wrong echo: refused.
	h.app.Stdin = strings.NewReader("nope\n")
	if code := h.run(t, "scan", "aws://", "--ack-authorized", "--out", out, "--engines", cloudaws.Name); code != ExitRefused {
		t.Fatalf("declined consent: %d", code)
	}
	h.app.IsTTY = false

	// 4b.4: prowler through its fake binary dedupes with the native engine
	// (one fingerprint for the root-MFA finding) and gets the documented argv.
	writeCloudConfig(t, h, awstest.DefaultAccount)
	fixture := filepath.Join(adaptertest.FixtureDir(t, "prowler", "4.3.5"), "prowler.ocsf.json")
	argvFile := adaptertest.Install(t, "prowler", "--version", "Prowler 4.3.5",
		`: > "$OUT/prowler.ocsf.json"; while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >> "$OUT/prowler.ocsf.json"; done < '`+fixture+`'`)
	both := filepath.Join(t.TempDir(), "both")
	if code := h.run(t, "scan", "aws://", "--ack-authorized", "--non-interactive", "--out", both, "--engines", cloudaws.Name+",adapter:prowler"); code != ExitOK {
		t.Fatalf("scan with prowler: %d %s", code, h.stderr.String())
	}
	scan, findings = readJSONReport(t, both)
	// The fixture carries two deliberately malformed elements, which the
	// adapter reports as an error after emitting every good finding (same
	// convention as nuclei/trivy): the run is "failed" with that count.
	st, errText := engineStatusAndError(scan, "adapter:prowler")
	if st != "failed" || !strings.Contains(errText, "2 element(s) were malformed") {
		t.Fatalf("prowler status %q: %s", st, errText)
	}
	rootMFA, eip := 0, 0
	for _, f := range findings {
		switch f["rule_id"] {
		case cloudaws.RuleRootMFADisabled:
			rootMFA++
		case "prowler:ec2_elastic_ip_unassigned":
			eip++
		}
	}
	if rootMFA != 1 || eip != 1 {
		t.Fatalf("dedupe: root-mfa=%d (want 1), prowler-only=%d (want 1)", rootMFA, eip)
	}
	argv := strings.Join(adaptertest.Argv(t, argvFile), " ")
	if !strings.HasPrefix(argv, "aws -M json-ocsf -o ") || !strings.HasSuffix(argv, " -F prowler -z -b --no-color -f us-east-1") || strings.Contains(argv, " -p ") {
		t.Fatalf("prowler argv: %s", argv)
	}

	// 4b.5: doctor and the IAM policy.
	if code := h.run(t, "doctor"); code != ExitOK {
		t.Fatalf("doctor: %d %s", code, h.stderr.String())
	}
	doc := h.stdout.String()
	for _, want := range []string{"aws credentials", "source env", "aws accounts", "1 allow-listed", "tool prowler"} {
		if !strings.Contains(doc, want) {
			t.Errorf("doctor missing %q:\n%s", want, doc)
		}
	}
	if code := h.run(t, "config", "show", "--aws-policy"); code != ExitOK {
		t.Fatal("config show --aws-policy")
	}
	var policy map[string]any
	if err := json.Unmarshal(h.stdout.Bytes(), &policy); err != nil || !strings.Contains(h.stdout.String(), `"iam:GetAccountSummary"`) || strings.Contains(h.stdout.String(), "Put") {
		t.Fatalf("policy: %v %s", err, h.stdout.String())
	}
}

func engineStatusAndError(scan map[string]any, name string) (string, string) {
	for _, e := range scan["engines"].([]any) {
		m := e.(map[string]any)
		if m["name"] == name {
			errText, _ := m["error"].(string)
			return m["status"].(string), errText
		}
	}
	return "", ""
}

// B8: fake key material appears in no file scnr writes and in nothing it
// prints at -v.
func TestNoCredentialLeak(t *testing.T) {
	cloudEnv(t)
	h := newHarness(t)
	srv := awstest.New(t, awstest.Fixture{})
	h.app.AWSEndpoint = srv.URL
	writeCloudConfig(t, h, awstest.DefaultAccount)
	out := filepath.Join(t.TempDir(), "out")
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	if code := h.run(t, "-v", "--audit-file", auditFile, "scan", "aws://", "--ack-authorized", "--non-interactive", "--out", out, "--format", "html,json,md,csv,sarif", "--engines", cloudaws.Name); code != ExitOK {
		t.Fatalf("scan: %d %s", code, h.stderr.String())
	}
	var files []string
	for _, root := range []string{h.home, out} {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
	}
	files = append(files, auditFile)
	if len(files) < 6 {
		t.Fatalf("expected db, reports and audit file, got %v", files)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{fakeAWSKey, fakeAWSSecret, fakeAWSToken} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s contains credential material", f)
			}
		}
	}
	for _, secret := range []string{fakeAWSKey, fakeAWSSecret, fakeAWSToken} {
		if strings.Contains(h.stderr.String(), secret) || strings.Contains(h.stdout.String(), secret) {
			t.Error("stdout/stderr contain credential material")
		}
	}
	if !strings.Contains(h.stderr.String(), "cloud-aws") {
		t.Fatalf("expected verbose progress on stderr: %s", h.stderr.String())
	}
}

// No flag exposes the AWS endpoint override (it exists for tests only).
func TestCLIDoesNotExposeEndpointOverride(t *testing.T) {
	root := NewApp("test").Root()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, fs := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
			fs.VisitAll(func(f *pflag.Flag) {
				l := strings.ToLower(f.Name)
				if strings.Contains(l, "endpoint") || strings.Contains(l, "aws") && !strings.Contains(l, "aws-policy") || strings.Contains(l, "base-url") {
					t.Errorf("%s exposes flag --%s", c.CommandPath(), f.Name)
				}
			})
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	// And the override is not read from the environment or the config.
	b, _ := os.ReadFile("scan.go")
	if strings.Contains(string(b), "AWS_ENDPOINT_URL") || strings.Contains(string(b), "Getenv") {
		t.Fatal("scan.go reads the environment for endpoints")
	}
}

// TestMarkFixedIgnoresPartialEngines (lifecycle rule): findings an engine
// did not re-observe because its coverage was truncated stay open. Run 1
// sees the fixture security groups; run 2 hits the pagination cap (the
// fixture groups are absent from the paged inventory) and is "partial":
// nothing is marked fixed. Run 3 is complete again: the groups reappear,
// still open, with no fixed-and-reopened churn.
func TestMarkFixedIgnoresPartialEngines(t *testing.T) {
	cloudEnv(t)
	h := newHarness(t)
	full := awstest.New(t, awstest.Fixture{})
	paged := awstest.New(t, awstest.Fixture{SecurityGroupPages: 101})
	writeCloudConfig(t, h, awstest.DefaultAccount)
	out := filepath.Join(t.TempDir(), "out")
	run := func(srvURL string) map[string]any {
		h.app.AWSEndpoint = srvURL
		if code := h.run(t, "scan", "aws://", "--ack-authorized", "--non-interactive", "--out", out, "--engines", cloudaws.Name); code != ExitOK {
			t.Fatalf("scan: %d %s", code, h.stderr.String())
		}
		scan, _ := readJSONReport(t, out)
		return scan
	}
	run(full.URL)
	sgOpen := func() []domain.Finding {
		var got []domain.Finding
		all, err := h.store(t).ListFindings(context.Background(), store.FindingFilter{AssetKey: "aws:" + awstest.DefaultAccount, Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range all {
			if f.RuleID == cloudaws.RuleSGOpenAll {
				got = append(got, f)
			}
		}
		return got
	}
	if fs := sgOpen(); len(fs) != 1 || fs[0].Status != domain.StatusOpen {
		t.Fatalf("after run 1: %+v", fs)
	}
	scan := run(paged.URL)
	if st, _ := engineStatus(scan, cloudaws.Name); !strings.HasPrefix(st, "partial: ") {
		t.Fatalf("run 2 status %q", st)
	}
	if strings.Contains(h.stdout.String(), "fixed since last scan") && !strings.Contains(h.stdout.String(), "0 fixed since last scan") {
		t.Fatalf("partial run marked findings fixed: %s", h.stdout.String())
	}
	if fs := sgOpen(); len(fs) != 1 || fs[0].Status != domain.StatusOpen {
		t.Fatalf("after partial run 2 the finding must stay open: %+v", fs)
	}
	// Unit-level: okEngines never lists a partial or skipped engine.
	ok := okEngines([]domain.EngineRun{{Name: "a", Status: "ok"}, {Name: "b", Status: "partial: budget"}, {Name: "c", Status: "skipped: x"}, {Name: "d", Status: "failed"}})
	if len(ok) != 1 || ok[0] != "a" {
		t.Fatalf("okEngines: %v", ok)
	}
}
