package prowler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/adapter/adaptertest"
	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	cloudaws "github.com/iamstoick/scnr/internal/engine/cloud/aws"
)

const account = "123456789012"

func confirmed(profile string) domain.Target {
	t := domain.Target{Raw: "aws://" + profile, Type: domain.TargetCloud, Value: Scheme + account}
	if profile != "" {
		t.Labels = map[string]string{"profile": profile}
	}
	return t
}

func nativeRules(t *testing.T) engine.RuleSet {
	t.Helper()
	e, err := cloudaws.New(config.CloudAWS{})
	if err != nil {
		t.Fatal(err)
	}
	return e.Rules()
}

// installFake puts a fake prowler on PATH that copies fixture into the
// output directory given after -o under the documented file name.
func installFake(t *testing.T, version, fixture string) string {
	t.Helper()
	body := `: > "$OUT/` + outputFile + `"; while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >> "$OUT/` + outputFile + `"; done < '` + fixture + `'`
	return adaptertest.Install(t, "prowler", "--version", "Prowler "+version, body)
}

func collect(t *testing.T, a *Adapter, path string) ([]domain.Finding, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []domain.Finding
	perr := a.Parse(f, func(fd domain.Finding) error { out = append(out, fd); return nil })
	return out, perr
}

// Every dedupe target is a real native rule.
func TestDedupeMapTargetsExist(t *testing.T) {
	rules := nativeRules(t)
	m, err := Dedupe()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) < 25 {
		t.Fatalf("dedupe map has %d entries", len(m))
	}
	for k, v := range m {
		if _, ok := rules[v]; !ok {
			t.Errorf("%s -> %s: no such native rule", k, v)
		}
	}
}

// Acceptance 4b.4: both fixture versions parse; mapped checks carry the
// native rule id and prose (one fingerprint with the native engine);
// unmapped ones are prowler:<check>; PASS/MANUAL are skipped; malformed
// elements are counted; nothing outside the allowlist leaks.
func TestParseFixtures(t *testing.T) {
	rules := nativeRules(t)
	for _, ver := range []string{"4.3.5", "5.2.0"} {
		a, err := New(nil, rules)
		if err != nil {
			t.Fatal(err)
		}
		findings, perr := collect(t, a, filepath.Join(adaptertest.FixtureDir(t, "prowler", ver), outputFile))
		if perr == nil || !strings.Contains(perr.Error(), "2 element(s) were malformed") {
			t.Fatalf("%s: bad-element report: %v", ver, perr)
		}
		byRule := map[string]domain.Finding{}
		for _, f := range findings {
			byRule[f.RuleID] = f
			if f.AssetKey != "aws:"+account || f.Engine != Name || f.Fingerprint == "" || len(f.Evidence) != 1 {
				t.Errorf("%s: shape %+v", ver, f)
			}
			all := f.Title + f.WhatItIs + f.HowToFix + f.Evidence[0].Redacted + strings.Join(f.References, " ")
			if strings.Contains(all, "CANARY") || strings.Contains(all, "hunter2") || strings.Contains(all, "abc.def.ghi") || strings.ContainsRune(all, 0x07) {
				t.Errorf("%s: non-allowlisted or unredacted content in %s: %q", ver, f.RuleID, all)
			}
		}
		if len(findings) != 5 {
			t.Fatalf("%s: %d findings: %v", ver, len(findings), byRule)
		}
		root, ok := byRule[cloudaws.RuleRootMFADisabled]
		if !ok || root.Location != "arn:aws:iam::"+account+":root" || root.Title != rules[cloudaws.RuleRootMFADisabled].Title || root.Severity != domain.Critical {
			t.Fatalf("%s: mapped root finding: %+v", ver, root)
		}
		if !strings.HasSuffix(root.HowToFix, "(remediation from prowler)") {
			t.Errorf("%s: mapped finding should carry prowler's remediation: %q", ver, root.HowToFix)
		}
		if root.Fingerprint != domain.Fingerprint(cloudaws.RuleRootMFADisabled, "aws:"+account, root.Location) {
			t.Errorf("%s: fingerprint does not match the native scheme", ver)
		}
		if _, ok := byRule[cloudaws.RuleSGOpenSSH]; !ok {
			t.Errorf("%s: security-group check not mapped (uid fallback): %v", ver, byRule)
		}
		eip, ok := byRule["prowler:ec2_elastic_ip_unassigned"]
		if !ok || eip.Severity != domain.Low || len(eip.References) != 1 || !strings.Contains(eip.HowToFix, "Release the address.") {
			t.Fatalf("%s: unmapped finding: %+v", ver, eip)
		}
		if lambda, ok := byRule["prowler:awslambda_function_url_public"]; !ok || lambda.Location != "aws:AwsLambdaFunction/fn-1" {
			t.Fatalf("%s: non-ARN resource location: %+v", ver, lambda)
		}
		for _, skipped := range []string{"prowler:iam_support_role_created", cloudaws.RuleUserWithoutMFA} {
			if _, ok := byRule[skipped]; ok {
				t.Errorf("%s: PASS/MANUAL element produced %s", ver, skipped)
			}
		}
	}
	// Without native rules the mapped id still dedupes; prose is prowler's.
	a, _ := New(nil, nil)
	findings, _ := collect(t, a, filepath.Join(adaptertest.FixtureDir(t, "prowler", "4.3.5"), outputFile))
	for _, f := range findings {
		if f.RuleID == cloudaws.RuleRootMFADisabled && !strings.Contains(f.WhatItIs, "iam_root_mfa_enabled") {
			t.Fatalf("fallback prose: %+v", f)
		}
	}
}

// B9 (adapter side) and acceptance 4b.4: the fake binary receives exactly
// the documented argv; the profile and regions come from the gate/scope.
func TestArgsAndFakeBinary(t *testing.T) {
	argvFile := installFake(t, "4.3.5", filepath.Join(adaptertest.FixtureDir(t, "prowler", "4.3.5"), outputFile))
	a, err := New([]string{"us-east-1", "eu-west-1"}, nativeRules(t))
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	o := engine.Options{Scratch: scratch}
	args, err := a.Args(confirmed("audit"), o)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aws", "-M", "json-ocsf", "-o", scratch, "-F", "prowler", "-z", "-b", "--no-color", "-p", "audit", "-f", "us-east-1", "eu-west-1"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("argv:\n got %v\nwant %v", args, want)
	}
	if err := adapter.CheckForbidden(args); err != nil {
		t.Fatal(err)
	}
	// No profile, no regions: the flags are absent, not empty.
	b, _ := New(nil, nil)
	args, _ = b.Args(confirmed(""), o)
	if j := strings.Join(args, " "); strings.Contains(j, "-p") || strings.Contains(j, "-f") {
		t.Fatalf("argv without profile/regions: %v", args)
	}
	// Unconfirmed target (profile form) is refused at the argv boundary.
	if _, err := a.Args(domain.Target{Type: domain.TargetCloud, Value: "aws://audit"}, o); err == nil {
		t.Fatal("unconfirmed target accepted")
	}
	if _, err := a.Args(confirmed("-p evil"), o); err == nil {
		t.Fatal("flag-shaped profile accepted")
	}
	// Full run through the fake: argv recorded, output parsed.
	var got []domain.Finding
	err = a.Run(context.Background(), confirmed("audit"), o, func(f domain.Finding) error { got = append(got, f); return nil })
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("run: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("%d findings via fake binary", len(got))
	}
	if recorded := adaptertest.Argv(t, argvFile); strings.Join(recorded, " ") != strings.Join(want, " ") {
		t.Fatalf("fake binary argv: %v", recorded)
	}
	if a.Version() != "4.3.5" {
		t.Fatalf("version: %q", a.Version())
	}
}

// B10: elements for another account are dropped and reported once.
func TestProwlerAccountMismatch(t *testing.T) {
	installFake(t, "4.3.5", filepath.Join(adaptertest.FixtureDir(t, "prowler", "4.3.5"), "mismatch.ocsf.json"))
	a, err := New(nil, nativeRules(t))
	if err != nil {
		t.Fatal(err)
	}
	var got []domain.Finding
	if err := a.Run(context.Background(), confirmed(""), engine.Options{Scratch: t.TempDir()}, func(f domain.Finding) error { got = append(got, f); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings: %+v", got)
	}
	var mismatch *domain.Finding
	for i := range got {
		if got[i].AssetKey != "aws:"+account {
			t.Fatalf("finding for another account emitted: %+v", got[i])
		}
		if got[i].RuleID == RuleAccountMismatch {
			mismatch = &got[i]
		}
	}
	if mismatch == nil || mismatch.Severity != domain.High || mismatch.Confidence != domain.Confirmed || !strings.Contains(mismatch.WhatItIs, "999999999999") || mismatch.Location != "prowler:account/999999999999" {
		t.Fatalf("mismatch finding: %+v", mismatch)
	}
}

// Missing binary: skipped with the doctor hint, never failed.
func TestMissingProwlerSkips(t *testing.T) {
	adaptertest.Hide(t)
	a, _ := New(nil, nil)
	err := a.Run(context.Background(), confirmed(""), engine.Options{Scratch: t.TempDir()}, func(domain.Finding) error { return nil })
	var skip *engine.SkipError
	if !errors.As(err, &skip) || !strings.Contains(skip.Reason, "scnr doctor") {
		t.Fatalf("want SkipError with doctor hint, got %v", err)
	}
	// Too-old prowler is skipped too.
	installFake(t, "3.9.0", filepath.Join(adaptertest.FixtureDir(t, "prowler", "4.3.5"), outputFile))
	err = a.Run(context.Background(), confirmed(""), engine.Options{Scratch: t.TempDir()}, func(domain.Finding) error { return nil })
	if !errors.As(err, &skip) || !strings.Contains(skip.Reason, "older") {
		t.Fatalf("old version: %v", err)
	}
}

// Element cap: a report with more than maxElements entries is partial.
func TestParseElementCap(t *testing.T) {
	a, _ := New(nil, nil)
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i <= maxElements; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"status_code":"PASS"}`)
	}
	sb.WriteString("]")
	err := a.Parse(strings.NewReader(sb.String()), func(domain.Finding) error { return nil })
	var pe *engine.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("want PartialError, got %v", err)
	}
	if err := a.Parse(strings.NewReader(`{"not":"an array"}`), func(domain.Finding) error { return nil }); err == nil {
		t.Fatal("object accepted as OCSF report")
	}
}
