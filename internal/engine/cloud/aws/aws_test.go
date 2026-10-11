package aws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/engine/cloud/aws/awstest"
	"github.com/iamstoick/scnr/internal/safety"
)

const (
	fakeKey    = "AKIAFAKEFAKEFAKEFAKE"
	fakeSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYXX"
	fakeToken  = "FQoGZXIvYXdzEBYaDFAKETOKENFAKETOKEN"
)

// envCreds points the chain at static environment keys and an isolated
// shared-config location so a developer's ~/.aws is never read.
func envCreds(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", fakeKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", fakeSecret)
	t.Setenv("AWS_SESSION_TOKEN", fakeToken)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ROLE_ARN", "")
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
}

// noEnvCreds clears every environment source so only files are consulted.
func noEnvCreds(t *testing.T) {
	t.Helper()
	envCreds(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
}

func newEngine(t *testing.T, srv *awstest.Server, cfg config.CloudAWS) *Engine {
	t.Helper()
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.BaseEndpoint = srv.URL
	e.EndpointHosts = []string{srv.Host()}
	e.HTTPTimeout = 10 * time.Second
	return e
}

func confirmedTarget(account string) domain.Target {
	return domain.Target{Raw: "aws://", Type: domain.TargetCloud, Value: Scheme + account}
}

type collector struct {
	mu       sync.Mutex
	findings []domain.Finding
}

func (c *collector) emit(f domain.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, f)
	return nil
}

func (c *collector) rules() []string {
	seen := map[string]bool{}
	for _, f := range c.findings {
		seen[f.RuleID] = true
	}
	var out []string
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func options(profile string) engine.Options {
	p, _ := engine.ProfileByName(profile)
	return engine.Options{Profile: p, Redactor: safety.NewRedactor()}
}

// TestRunFixtureFindings: the default fixture yields a finding for every
// rule it models, located at ARNs, on the account asset.
func TestRunFixtureFindings(t *testing.T) {
	envCreds(t)
	srv := awstest.New(t, awstest.Fixture{})
	e := newEngine(t, srv, config.CloudAWS{Regions: []string{"us-east-1"}})
	id, err := e.Identity(context.Background(), domain.Target{Type: domain.TargetCloud, Value: "aws://"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Account != awstest.DefaultAccount || id.Source != SourceEnv || !strings.HasPrefix(id.Principal, "arn:aws:iam::") {
		t.Fatalf("identity: %+v", id)
	}
	var c collector
	if err := e.Run(context.Background(), confirmedTarget(id.Account), options("standard"), c.emit); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{
		RuleRootMFADisabled, RuleRootAccessKeys, RuleUserWithoutMFA, RulePasswordPolicyMissing, RuleAccessKeyStale,
		RuleBucketPublic, RulePublicAccessBlockMissing, RuleBucketEncryptionDisabled, RuleBucketLoggingDisabled,
		RuleSGOpenSSH, RuleSGOpenRDP, RuleSGOpenAll, RuleDefaultSGAllowsTraffic, RuleEBSVolumeUnencrypted, RuleEBSDefaultEncryption, RuleIMDSv1Allowed,
		RuleRDSPublic, RuleRDSUnencrypted, RuleRDSBackupsDisabled,
		RuleTrailNotMultiRegion, RuleTrailValidationDisabled, RuleTrailNotLogging,
		RuleKMSRotationDisabled,
	}
	sort.Strings(want)
	if got := c.rules(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rules:\n got %v\nwant %v", got, want)
	}
	for _, f := range c.findings {
		if f.AssetKey != "aws:"+awstest.DefaultAccount || !strings.HasPrefix(f.Location, "arn:aws:") || f.Engine != Name || len(f.Evidence) != 1 || f.Evidence[0].Location != f.Location {
			t.Errorf("finding shape: %+v", f)
		}
		if f.Title == "" || f.HowToFix == "" {
			t.Errorf("rule prose missing for %s", f.RuleID)
		}
	}
	// Clean resources produce nothing: bob, private-logs, sg-clean, db-ok, the encrypted volume, the IMDSv2 instance.
	for _, f := range c.findings {
		for _, clean := range []string{"user/bob", "private-logs", "sg-0clean", "db:db-ok", "vol-0enc", "i-0v2"} {
			if strings.Contains(f.Location, clean) {
				t.Errorf("finding on clean resource: %s %s", f.RuleID, f.Location)
			}
		}
	}
	// The two remaining rules come from fixture variants.
	srv2 := awstest.New(t, awstest.Fixture{WeakPasswordPolicy: true, NoTrails: true})
	e2 := newEngine(t, srv2, config.CloudAWS{Regions: []string{"us-east-1"}})
	var c2 collector
	if err := e2.Run(context.Background(), confirmedTarget(awstest.DefaultAccount), options("standard"), c2.emit); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(c2.rules(), ",")
	for _, r := range []string{RulePasswordPolicyWeak, RuleTrailMissing} {
		if !strings.Contains(got, r) {
			t.Errorf("variant fixture missing %s: %s", r, got)
		}
	}
	for _, r := range []string{RulePasswordPolicyMissing, RuleTrailNotLogging} {
		if strings.Contains(got, r) {
			t.Errorf("variant fixture should not emit %s", r)
		}
	}
}

// B7: nothing from the forbidden fields reaches a finding, and no check
// source references such a field.
func TestNoForbiddenFieldsInEvidence(t *testing.T) {
	envCreds(t)
	srv := awstest.New(t, awstest.Fixture{})
	e := newEngine(t, srv, config.CloudAWS{Regions: []string{"us-east-1"}})
	var c collector
	if err := e.Run(context.Background(), confirmedTarget(awstest.DefaultAccount), options("standard"), c.emit); err != nil {
		t.Fatal(err)
	}
	if len(c.findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range c.findings {
		all := strings.Join([]string{f.Title, f.WhatItIs, f.WhyItMatters, f.HowToFix, f.Location}, " ")
		for _, ev := range f.Evidence {
			all += " " + ev.Redacted + " " + ev.Location
		}
		if strings.Contains(all, awstest.Canary) {
			t.Fatalf("canary leaked into finding %s: %s", f.RuleID, all)
		}
		if strings.Contains(all, "AKIA") || strings.Contains(all, fakeSecret) {
			t.Fatalf("credential material in finding %s: %s", f.RuleID, all)
		}
	}
	// Static check: the selectors that would read those fields.
	forbidden := []string{"Tags", "TagList", "TagSet", "UserData", "PolicyDocument", "Environment", "Description", "GroupDescription", "MasterUsername", "S3BucketName", "Policy", "DisplayName"}
	files, _ := filepath.Glob("checks_*.go")
	if len(files) < 6 {
		t.Fatalf("checks files: %v", files)
	}
	for _, f := range files {
		for _, sel := range forbiddenSelectors(t, f, forbidden) {
			t.Errorf("%s: forbidden selector .%s", f, sel)
		}
	}
}

// B1: a mutating operation never leaves the process.
func TestReadOnlyGuardRefuses(t *testing.T) {
	envCreds(t)
	srv := awstest.New(t, awstest.Fixture{})
	e := newEngine(t, srv, config.CloudAWS{})
	s, err := e.session(context.Background(), "", options("standard").Profile)
	if err != nil {
		t.Fatal(err)
	}
	before := len(srv.Requests())
	cl := s.clients(globalRegion)
	ctx := context.Background()
	var roe *RefusedOperationError
	if _, err := cl.s3.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: awssdk.String("public-data"), Policy: awssdk.String("{}")}); !errors.As(err, &roe) || roe.Op != "PutBucketPolicy" {
		t.Fatalf("PutBucketPolicy: %v", err)
	}
	if _, err := cl.iam.DeleteUser(ctx, &iam.DeleteUserInput{UserName: awssdk.String("alice")}); !errors.As(err, &roe) || roe.Op != "DeleteUser" {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := cl.iam.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); !errors.As(err, &roe) || roe.Op != "GenerateCredentialReport" {
		t.Fatalf("GenerateCredentialReport: %v", err)
	}
	// The credential-chain STS client refuses everything but its three ops.
	if _, err := s.stsClient(s.creds).GetSessionToken(ctx, nil); !errors.As(err, &roe) {
		t.Fatalf("GetSessionToken through the credential guard: %v", err)
	}
	if n := len(srv.Requests()) - before; n != 0 {
		t.Fatalf("%d request(s) reached the server: %v", n, srv.Requests()[before:])
	}
	// A read-only operation still works through the same client.
	if _, err := cl.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{}); err != nil {
		t.Fatal(err)
	}
}

// B3: account binding through the gate and the mid-run identity re-check.
func TestCloudGateAccountAllowlist(t *testing.T) {
	noEnvCreds(t)
	os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[audit]\naws_access_key_id = "+fakeKey+"\naws_secret_access_key = "+fakeSecret+"\n"), 0o600)
	srv := awstest.New(t, awstest.Fixture{})
	e := newEngine(t, srv, config.CloudAWS{Regions: []string{"us-east-1"}})
	target := domain.Target{Raw: "aws://audit", Type: domain.TargetCloud, Value: "aws://audit"}
	gate := &safety.Gate{Acknowledged: true, CloudIdentity: e.Identity, CloudAccounts: []string{"999999999999"}}
	_, err := gate.Decide(context.Background(), target, "")
	var ref *safety.RefusalError
	if !errors.As(err, &ref) || ref.Code != safety.CodeCloudAccountNotAllowed {
		t.Fatalf("non-interactive mismatch: %v", err)
	}
	// Interactive: the prompt receives the account id as the expected echo.
	var asked domain.Target
	gate.Consent = func(_ context.Context, t domain.Target, plan string) (bool, error) {
		asked = t
		if !strings.Contains(plan, awstest.DefaultAccount) || !strings.Contains(plan, "credentials from profile:audit") {
			return false, errors.New("plan missing identity: " + plan)
		}
		return true, nil
	}
	dec, err := gate.Decide(context.Background(), target, "")
	if err != nil {
		t.Fatal(err)
	}
	if dec.ConsentMethod != domain.ConsentInteractive || asked.Hostname != awstest.DefaultAccount || dec.Target.Value != Scheme+awstest.DefaultAccount || dec.Target.Labels["profile"] != "audit" || dec.Target.AssetKey() != "aws:"+awstest.DefaultAccount {
		t.Fatalf("decision: %+v target %+v", dec, dec.Target)
	}
	// Allowlisted: no prompt.
	gate.Consent = func(context.Context, domain.Target, string) (bool, error) {
		return false, errors.New("must not prompt")
	}
	gate.CloudAccounts = []string{awstest.DefaultAccount}
	dec, err = gate.Decide(context.Background(), target, "")
	if err != nil || dec.ConsentMethod != domain.ConsentCloudAllowlist || dec.Identity == nil || dec.Identity.Source != "profile:audit" {
		t.Fatalf("allowlisted: %+v %v", dec, err)
	}
	// Identity change mid-run: the engine fails, the Runner records failed.
	// The gate consulted the session for profile "audit"; Run reuses it.
	srv.SetAccount("999999999999")
	runner := &engine.Runner{}
	runs, _ := runner.Run(context.Background(), []engine.Engine{e}, dec.Target, options("standard"), func(domain.Finding) error { return nil })
	if len(runs) != 1 || runs[0].Status != "failed" || !strings.Contains(runs[0].Error, "identity changed") {
		t.Fatalf("runs: %+v", runs)
	}
	// A target that was never confirmed by the gate is refused by Run.
	if err := e.Run(context.Background(), domain.Target{Type: domain.TargetCloud, Value: "aws://audit"}, options("standard"), func(domain.Finding) error { return nil }); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("unconfirmed target: %v", err)
	}
}

// B4: credential_process and SSO profiles are refused before any call;
// instance credentials need the scope-file flag; the refusals carry
// E_CLOUD_CREDENTIAL_SOURCE and the fake sees no request.
func TestCredentialSourcesRefused(t *testing.T) {
	noEnvCreds(t)
	srv := awstest.New(t, awstest.Fixture{})
	cfg := os.Getenv("AWS_CONFIG_FILE")
	os.WriteFile(cfg, []byte(`[profile helper]
credential_process = /usr/bin/evil-helper
region = us-east-1

[profile sso]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = Audit

[profile instance]
credential_source = Ec2InstanceMetadata
role_arn = arn:aws:iam::123456789012:role/Audit

[profile chain]
role_arn = arn:aws:iam::123456789012:role/Audit
source_profile = static
`), 0o600)
	os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[static]\naws_access_key_id = "+fakeKey+"\naws_secret_access_key = "+fakeSecret+"\n"), 0o600)
	for _, tc := range []struct{ profile, want string }{
		{"helper", "credential_process"},
		{"sso", "SSO"},
		{"instance", "instance_credentials"},
		{"missing", "missing"},
	} {
		e := newEngine(t, srv, config.CloudAWS{})
		_, err := e.Identity(context.Background(), domain.Target{Type: domain.TargetCloud, Value: "aws://" + tc.profile})
		var ref *safety.RefusalError
		if !errors.As(err, &ref) || ref.Code != safety.CodeCloudCredentialSource || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.profile, err)
		}
	}
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("refused profiles made %d request(s): %v", n, srv.Requests())
	}
	// doctor's description resolves nothing either.
	if _, err := DescribeCredentialSource(context.Background(), "helper", false); err == nil {
		t.Fatal("DescribeCredentialSource accepted credential_process")
	}
	// A role_arn profile chains through static keys and the guarded STS
	// client; AssumeRole is the one non-read operation and it is allowed.
	srv2 := awstest.New(t, awstest.Fixture{AssumeRole: true})
	e := newEngine(t, srv2, config.CloudAWS{})
	id, err := e.Identity(context.Background(), domain.Target{Type: domain.TargetCloud, Value: "aws://chain"})
	if err != nil || id.Source != "profile:chain" {
		t.Fatalf("chain: %+v %v", id, err)
	}
	if srv2.Count("AssumeRole") != 1 || srv2.Count("GetCallerIdentity") != 1 {
		t.Fatalf("chain requests: %v", srv2.Requests())
	}
	desc, err := DescribeCredentialSource(context.Background(), "chain", false)
	if err != nil || !strings.Contains(desc, "role arn:aws:iam::123456789012:role/Audit via profile:static") {
		t.Fatalf("describe chain: %q %v", desc, err)
	}
	// Nothing resolved an endpoint on the metadata network.
	for _, r := range append(srv.Requests(), srv2.Requests()...) {
		if strings.Contains(r.Path, "169.254") {
			t.Fatalf("metadata request: %+v", r)
		}
	}
}

// B6: a 101-page inventory list is cut at the cap, reported once as
// inventory-truncated and the engine returns PartialError (Runner status
// "partial: ...").
func TestInventoryTruncated(t *testing.T) {
	envCreds(t)
	srv := awstest.New(t, awstest.Fixture{SecurityGroupPages: maxPages + 1})
	e := newEngine(t, srv, config.CloudAWS{Regions: []string{"us-east-1"}})
	var c collector
	err := e.Run(context.Background(), confirmedTarget(awstest.DefaultAccount), options("standard"), c.emit)
	var pe *engine.PartialError
	if !errors.As(err, &pe) || !strings.Contains(pe.Reason, "truncated") {
		t.Fatalf("want PartialError, got %v", err)
	}
	trunc := 0
	for _, f := range c.findings {
		if f.RuleID == RuleInventoryTruncated {
			trunc++
			if !strings.Contains(f.Evidence[0].Redacted, "ec2:DescribeSecurityGroups") || !strings.Contains(f.Evidence[0].Redacted, "pages=100") {
				t.Errorf("truncation evidence: %s", f.Evidence[0].Redacted)
			}
		}
	}
	if trunc != 1 {
		t.Fatalf("inventory-truncated findings: %d", trunc)
	}
	if n := srv.Count("DescribeSecurityGroups"); n != maxPages {
		t.Fatalf("DescribeSecurityGroups calls: %d", n)
	}
	runner := &engine.Runner{}
	runs, _ := runner.Run(context.Background(), []engine.Engine{newEngine(t, srv, config.CloudAWS{Regions: []string{"us-east-1"}})}, confirmedTarget(awstest.DefaultAccount), options("standard"), func(domain.Finding) error { return nil })
	if len(runs) != 1 || !strings.HasPrefix(runs[0].Status, "partial: ") {
		t.Fatalf("runner status: %+v", runs)
	}
}

// Budget: once the scan-wide budget is spent the run stops, emits one
// truncation finding and is partial.
func TestBudgetExhaustedIsPartial(t *testing.T) {
	envCreds(t)
	srv := awstest.New(t, awstest.Fixture{})
	e := newEngine(t, srv, config.CloudAWS{Regions: []string{"us-east-1"}})
	s, err := e.session(context.Background(), "", options("standard").Profile)
	if err != nil {
		t.Fatal(err)
	}
	s.budget = newBudget(4) // identity call already made; one reserved for the re-check, very little left
	var c collector
	err = e.Run(context.Background(), confirmedTarget(awstest.DefaultAccount), options("standard"), c.emit)
	var pe *engine.PartialError
	if !errors.As(err, &pe) || !strings.Contains(pe.Reason, "budget") {
		t.Fatalf("want PartialError(budget), got %v", err)
	}
	n := 0
	for _, f := range c.findings {
		if f.RuleID == RuleInventoryTruncated && strings.Contains(f.Location, "inventory/budget") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("budget findings: %d", n)
	}
	if calls := len(srv.Requests()); calls > 5 {
		t.Fatalf("budget did not stop the run: %d calls", calls)
	}
}

// The gate caches the session through Identity with an empty profile; Run
// must install the run's profile before any check runs, or a deep scan
// silently gets the standard budget and rate while Plan advertises deep.
// Pure unit test (no fake server): the wiring through Run is covered by
// TestBudgetExhaustedIsPartial, which relies on the same-profile no-op.
func TestSetProfileAppliesRunProfile(t *testing.T) {
	s := &session{budget: newBudget(budgetFor(engine.Profile{})), rate: rateFor(engine.Profile{})}
	deep, err := engine.ProfileByName("deep")
	if err != nil {
		t.Fatal(err)
	}
	if !s.budget.take() {
		t.Fatal("fresh budget refuses")
	}
	before := s.budget.used()
	s.setProfile(deep)
	if s.budget.total != budgetDeep || s.rate != rateDeep || s.profName != "deep" {
		t.Fatalf("deep not installed: total=%d rate=%d prof=%q", s.budget.total, s.rate, s.profName)
	}
	if got := s.budget.used(); got != before {
		t.Fatalf("spent calls lost in the switch: used=%d, want %d", got, before)
	}
	// Same profile: untouched, so a test-installed budget survives.
	s.budget = newBudget(4)
	s.setProfile(deep)
	if s.budget.total != 4 {
		t.Fatalf("same-profile setProfile reset the budget: total=%d", s.budget.total)
	}
}

// Context cancellation stops the run promptly with the context error.
func TestRunHonoursContext(t *testing.T) {
	envCreds(t)
	srv := awstest.New(t, awstest.Fixture{SecurityGroupPages: 50})
	e := newEngine(t, srv, config.CloudAWS{Regions: []string{"us-east-1"}})
	if _, err := e.Identity(context.Background(), domain.Target{Type: domain.TargetCloud, Value: "aws://"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := e.Run(ctx, confirmedTarget(awstest.DefaultAccount), options("standard"), func(domain.Finding) error { return nil })
	if err == nil || !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("want context error, got %v", err)
	}
}

// The IAM policy printed for operators names every operation (B2 pins
// the operation list itself to the sources).
func TestIAMPolicyMatchesOperations(t *testing.T) {
	doc := IAMPolicyJSON()
	for _, op := range Operations {
		if !strings.Contains(doc, `"`+op+`"`) {
			t.Errorf("policy missing %s", op)
		}
	}
	if !strings.Contains(doc, `"Effect": "Allow"`) || strings.Contains(doc, "Put") || strings.Contains(doc, "Delete") {
		t.Fatalf("policy document: %s", doc)
	}
}
