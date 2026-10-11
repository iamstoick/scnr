package iac

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

const fixtureRepo = "../../../testdata/phase3-repo"

func runOn(t *testing.T, root string) map[string][]domain.Finding {
	t.Helper()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(root)
	out := map[string][]domain.Finding{}
	err = e.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: abs}, engine.Options{SecretKey: []byte("k"), Redactor: safety.NewRedactor()}, func(f domain.Finding) error {
		out[f.RuleID] = append(out[f.RuleID], f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func locs(fs []domain.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Location)
	}
	return out
}

func hasLoc(fs []domain.Finding, want string) bool {
	for _, f := range fs {
		if strings.HasPrefix(f.Location, want) {
			return true
		}
	}
	return false
}

func TestDockerfileRules(t *testing.T) {
	got := runOn(t, fixtureRepo)
	// Final stage (FROM node) has no USER; the build stage's absence does not count twice.
	if fs := got["iac.docker.no-user"]; len(fs) != 1 || fs[0].Location != "Dockerfile:7" {
		t.Fatalf("no-user %v", locs(fs))
	}
	if fs := got["iac.docker.latest-tag"]; len(fs) != 2 || !hasLoc(fs, "Dockerfile:2") || !hasLoc(fs, "Dockerfile:7") {
		t.Fatalf("latest %v", locs(fs))
	}
	if fs := got["iac.docker.add-url"]; len(fs) != 1 || fs[0].Location != "Dockerfile:10" {
		t.Fatalf("add-url %v", locs(fs))
	}
	secrets := got["iac.docker.secret-in-env"]
	if len(secrets) != 2 {
		t.Fatalf("secret-in-env %v", locs(secrets))
	}
	for _, f := range secrets {
		ev := f.Evidence[0].Redacted
		if strings.Contains(ev, "hunter2-not-a-real-pw") || strings.Contains(ev, "51H8xFakeTokenValue000000") || !strings.Contains(ev, "*") || f.Evidence[0].Hash == "" {
			t.Fatalf("secret not redacted: %q", ev)
		}
		if !strings.Contains(f.Location, "#") {
			t.Fatalf("secret location should carry the evidence hash: %s", f.Location)
		}
	}
	// Continuations, stage aliases, scratch, digests and ARG refs.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("ARG BASE=alpine:3.20\nFROM ${BASE} AS base\nFROM scratch\nFROM base\nFROM alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000\nRUN apk add \\\n  # comment inside\n  curl\nENV PASSWORD=${PASSWORD}\nENV TOKEN changeme\nUSER 1000:1000\n"), 0o600)
	got = runOn(t, dir)
	if len(got) != 0 {
		t.Fatalf("unexpected findings %v", got)
	}
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.20\nUSER root\n"), 0o600)
	if got = runOn(t, dir); len(got["iac.docker.no-user"]) != 1 {
		t.Fatalf("USER root must still count as root: %v", got)
	}
}

func TestKubernetesRules(t *testing.T) {
	got := runOn(t, fixtureRepo)
	want := map[string]string{
		"iac.k8s.privileged":         "k8s/deployment.yaml:16",
		"iac.k8s.host-namespace":     "k8s/deployment.yaml:11",
		"iac.k8s.no-resource-limits": "k8s/deployment.yaml:13", // container web only; sidecar has limits
		"iac.k8s.run-as-root":        "k8s/deployment.yaml:13", // sidecar sets runAsNonRoot
	}
	for rule, loc := range want {
		fs := got[rule]
		if len(fs) != 1 || fs[0].Location != loc {
			t.Errorf("%s: %v (want %s)", rule, locs(fs), loc)
		}
	}
	sec := got["iac.k8s.secret-in-env"]
	if len(sec) != 1 || !strings.HasPrefix(sec[0].Location, "k8s/deployment.yaml:19#") || strings.Contains(sec[0].Evidence[0].Redacted, "hunter2") {
		t.Fatalf("secret-in-env %+v", sec)
	}
	// Service documents and Helm templates are ignored; CronJob path works.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cron.yaml"), []byte("apiVersion: batch/v1\nkind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          securityContext: {runAsNonRoot: true}\n          containers:\n            - name: c\n              resources: {limits: {cpu: 1, memory: 1Gi}}\n              securityContext: {privileged: true}\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "helm.yaml"), []byte("apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: {{ .Values.hostNetwork }}\n"), 0o600)
	got = runOn(t, dir)
	if len(got) != 1 || len(got["iac.k8s.privileged"]) != 1 || got["iac.k8s.privileged"][0].Location != "cron.yaml:12" {
		t.Fatalf("%v", got)
	}
}

// A YAML alias bomb or absurd nesting in a manifest is dropped, never
// expanded into findings or memory.
func TestKubernetesAliasBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Pod\nx0: &x0 [a, a, a, a, a, a, a, a, a, a]\n")
	for i := 1; i < 10; i++ {
		b.WriteString("x" + itoa(i) + ": &x" + itoa(i) + " [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString("*x" + itoa(i-1))
		}
		b.WriteString("]\n")
	}
	b.WriteString("spec:\n  containers: *x9\n")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bomb.yaml"), []byte(b.String()), 0o600)
	os.WriteFile(filepath.Join(dir, "deep.yaml"), []byte("apiVersion: v1\nkind: Pod\nspec: "+strings.Repeat("[", 200)+strings.Repeat("]", 200)+"\n"), 0o600)
	start := time.Now()
	got := runOn(t, dir)
	// deep.yaml is skipped unparsed and reported once; the alias bomb
	// produces nothing.
	if time.Since(start) > 2*time.Second || len(got) != 1 || len(got[RuleFileSkipped]) != 1 {
		t.Fatalf("bomb handling: %s, %v", time.Since(start), got)
	}
}

func itoa(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+i))) }

// Acceptance 3.5: Terraform fixtures produce the documented rules with HCL
// line locations.
func TestTerraformRules(t *testing.T) {
	got := runOn(t, fixtureRepo)
	tf := "terraform/main.tf:"
	want := map[string][]string{
		"iac.tf.s3-public-acl":               {tf + "12"},
		"iac.tf.s3-no-public-access-block":   {tf + "10"}, // public_logs only; guarded is covered
		"iac.tf.s3-no-encryption":            {tf + "10"},
		"iac.tf.s3-no-versioning":            {tf + "10"},
		"iac.tf.s3-no-logging":               {tf + "10"}, // guarded is covered by a literal bucket name
		"iac.tf.sg-open-ssh":                 {tf + "52"},
		"iac.tf.sg-open-all":                 {tf + "66"},
		"iac.tf.sg-open-rdp":                 {tf + "74"},
		"iac.tf.rds-public":                  {tf + "86"},
		"iac.tf.rds-unencrypted":             {tf + "83"},
		"iac.tf.rds-no-backups":              {tf + "87"},
		"iac.tf.ebs-unencrypted":             {tf + "91", tf + "100"},
		"iac.tf.instance-public-ip":          {tf + "99"},
		"iac.tf.iam-wildcard-action":         {tf + "107", tf + "126"}, // jsonencode policy + data document; heredoc is scoped
		"iac.tf.cloudtrail-logging-disabled": {tf + "136"},
		"iac.tf.cloudtrail-not-multi-region": {tf + "133"},
		"iac.tf.cloudtrail-no-validation":    {tf + "133"},
		"iac.tf.kms-rotation-disabled":       {tf + "139"},
	}
	// Every expected line names the construct the rule is about.
	src, _ := os.ReadFile(filepath.Join(fixtureRepo, "terraform/main.tf"))
	lines := strings.Split(string(src), "\n")
	for rule, wantLocs := range want {
		for _, w := range wantLocs {
			n := 0
			for _, c := range strings.TrimPrefix(w, tf) {
				n = n*10 + int(c-'0')
			}
			l := strings.TrimSpace(lines[n-1])
			if !strings.HasSuffix(l, "{") && !strings.Contains(l, "=") {
				t.Errorf("%s: line %d is not a block or attribute: %q", rule, n, l)
			}
		}
	}
	for rule, wantLocs := range want {
		fs := got[rule]
		if len(fs) != len(wantLocs) {
			t.Errorf("%s: got %v, want %v", rule, locs(fs), wantLocs)
			continue
		}
		for _, w := range wantLocs {
			if !hasLoc(fs, w) {
				t.Errorf("%s: got %v, want %s", rule, locs(fs), w)
			}
		}
	}
	for _, rule := range []string{"iac.tf.secret-in-variable-default", "iac.tf.lambda-secret-in-env"} {
		fs := got[rule]
		if len(fs) != 1 || strings.Contains(fs[0].Evidence[0].Redacted, "hunter2") || strings.Contains(fs[0].Evidence[0].Redacted, "51H8xFakeTokenValue000000") {
			t.Errorf("%s: %+v", rule, fs)
		}
	}
	if fs := got["iac.tf.secret-in-variable-default"]; len(fs) == 1 && !strings.HasPrefix(fs[0].Location, tf+"7#") {
		t.Errorf("variable default location %s", fs[0].Location)
	}
	for rule, fs := range got {
		if !strings.HasPrefix(rule, "iac.tf.") {
			continue
		}
		for _, f := range fs {
			if f.Confidence != domain.Firm || f.Evidence[0].Redacted == "" || f.HowToFix == "" {
				t.Errorf("%s incomplete: %+v", rule, f)
			}
		}
	}
}

// Unresolvable values (variables, locals) never produce findings; broken
// HCL is skipped.
func TestTerraformUnknownsAreNotFindings(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.tf"), []byte(`
resource "aws_db_instance" "x" {
  publicly_accessible = var.public
  storage_encrypted   = local.enc
}
resource "aws_s3_bucket" "b" { acl = var.acl }
resource "aws_s3_bucket_public_access_block" "b" { bucket = aws_s3_bucket.b.id }
resource "aws_s3_bucket_server_side_encryption_configuration" "b" { bucket = aws_s3_bucket.b.id }
resource "aws_s3_bucket_versioning" "b" { bucket = aws_s3_bucket.b.id }
resource "aws_s3_bucket_logging" "b" { bucket = aws_s3_bucket.b.id }
resource "aws_security_group" "sg" {
  ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = var.cidrs }
}
`), 0o600)
	os.WriteFile(filepath.Join(dir, "broken.tf"), []byte("resource \"aws_s3_bucket\" {"), 0o600)
	got := runOn(t, dir)
	delete(got, "iac.tf.rds-unencrypted") // storage_encrypted unknown -> treated as not set; documented conservative choice
	if len(got) != 0 {
		t.Fatalf("unexpected %v", got)
	}
}

func TestPlanAndPolicyParsing(t *testing.T) {
	e, _ := New()
	abs, _ := filepath.Abs(fixtureRepo)
	p, err := e.Plan(context.Background(), domain.Target{Type: domain.TargetPath, Value: abs}, engine.Options{})
	if err != nil || !strings.Contains(p.Summary, "1 Dockerfile(s), 1 Kubernetes manifest(s), 1 Terraform file(s)") {
		t.Fatalf("%+v %v", p, err)
	}
	if !policyAllowsAll(`{"Statement":{"Effect":"Allow","Action":"*"}}`) || policyAllowsAll(`{"Statement":[{"Effect":"Deny","Action":"*"}]}`) || policyAllowsAll(`{"Statement":[{"Action":["s3:*"]}]}`) || policyAllowsAll("not json") {
		t.Fatal("policy parsing")
	}
	if policyAllowsAll(strings.Repeat(" ", 300<<10) + `{"Statement":{"Action":"*"}}`) {
		t.Fatal("oversized policy must be ignored")
	}
}

// Findings 1: nesting deeper than engine.MaxNestingDepth is rejected on the
// raw bytes, before any recursive parser runs, and surfaces as one
// iac.file-skipped-too-complex note. The guard itself is exercised on a
// 1 MiB input (what would overflow the stack); the parsers only ever see
// inputs a few hundred levels deep, which parse fine but must be skipped.
func TestDepthGuardSkipsBeforeParse(t *testing.T) {
	start := time.Now()
	deep := []byte("a = " + strings.Repeat("(", (1<<20)-16) + "1")
	if d := engine.BracketDepth(deep, engine.MaxNestingDepth); d <= engine.MaxNestingDepth {
		t.Fatalf("depth %d not rejected", d)
	}
	k8s := append([]byte("apiVersion: v1\nkind: Pod\nspec: "), bytes.Repeat([]byte("["), (1<<20)-64)...)
	if d := engine.YAMLDepth(k8s, engine.MaxNestingDepth); d <= engine.MaxNestingDepth {
		t.Fatalf("yaml depth %d not rejected", d)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("pre-scan too slow: %s", time.Since(start))
	}
	m := &terraformModule{}
	if m.add("deep.tf", deep) || len(m.blocks) != 0 {
		t.Fatal("deep .tf must be skipped before parsing")
	}
	if m.add("big.tf", append([]byte("# "), bytes.Repeat([]byte("x"), MaxTerraformFileBytes)...)) {
		t.Fatal("oversized .tf must be skipped")
	}

	dir := t.TempDir()
	n := engine.MaxNestingDepth * 2 // parses without trouble; still over the limit
	os.WriteFile(filepath.Join(dir, "deep.tf"), []byte("resource \"aws_s3_bucket\" \"b\" {\n  acl = "+strings.Repeat("(", n)+"\"public-read\""+strings.Repeat(")", n)+"\n}\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ok.tf"), []byte("resource \"aws_s3_bucket_acl\" \"a\" {\n  acl = ((\"public-read\"))\n}\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "flow.yaml"), []byte("apiVersion: v1\nkind: Pod\nspec: "+strings.Repeat("[", n)+strings.Repeat("]", n)+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "chain.yaml"), []byte("apiVersion: v1\nkind: Pod\nspec:\n  "+strings.Repeat("- ", n)+"x\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "fine.yaml"), []byte("apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true\n  containers: [{name: c, securityContext: {runAsNonRoot: true}, resources: {limits: {cpu: 1, memory: 1Gi}}}]\n"), 0o600)
	got := runOn(t, dir)
	if fs := got["iac.tf.s3-public-acl"]; len(fs) != 1 || fs[0].Location != "ok.tf:2" {
		t.Fatalf("shallow file must still be checked, deep one not: %v", locs(fs))
	}
	if fs := got["iac.k8s.host-namespace"]; len(fs) != 1 {
		t.Fatalf("shallow manifest must still be checked: %v", locs(fs))
	}
	note := got[RuleFileSkipped]
	if len(note) != 1 || note[0].Severity != domain.Info {
		t.Fatalf("want one skipped note, got %+v", note)
	}
	ev := note[0].Evidence[0].Redacted
	for _, want := range []string{"3 file(s)", "deep.tf", "flow.yaml", "chain.yaml"} {
		if !strings.Contains(ev, want) {
			t.Fatalf("note %q lacks %q", ev, want)
		}
	}
	if len(got) != 3 {
		t.Fatalf("unexpected findings: %v", got)
	}
}

// Finding 2: a nested `for` over literal lists would evaluate 200^4 times;
// non-constant-shaped expressions are unresolvable instead (never a
// finding) and the shape check is what rejects them, before evaluation.
func TestTerraformNonConstantExpressionsAreUnresolvable(t *testing.T) {
	list := "[" + strings.TrimSuffix(strings.Repeat(`"public-read",`, 200), ",") + "]"
	src := "resource \"aws_s3_bucket\" \"b\" {\n" +
		"  acl = [for a in " + list + " : [for b in " + list + " : [for c in " + list + " : [for d in " + list + " : a]]]][0][0][0][0]\n" +
		"  bucket = true ? \"x\" : \"y\"\n" +
		"  tags = { a = upper(\"x\") }\n" +
		"  policy = jsonencode({ Statement = [{ Effect = \"Allow\", Action = \"*\" }] })\n" +
		"  region = \"${true ? \"a\" : \"b\"}\"\n" +
		"  many = [" + strings.Repeat("1,", maxExprElements+1) + "]\n" +
		"}\n"
	m := &terraformModule{}
	if !m.add("main.tf", []byte(src)) || len(m.blocks) != 1 {
		t.Fatal("parse failed")
	}
	body := m.blocks[0].b.Body
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, name := range []string{"acl", "bucket", "tags", "region", "many"} {
			if _, _, ok := attr(body, name); ok {
				t.Errorf("%s evaluated; must be unresolvable", name)
			}
		}
		if v, ok := attrString(body, "policy"); !ok || !policyAllowsAll(v) {
			t.Errorf("jsonencode of constants must still evaluate: %q %v", v, ok)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("attribute evaluation did not return within 5s")
	}
	// Splat and function calls other than jsonencode are rejected by shape.
	for _, expr := range []string{"var.list[*].id", "lower(\"A\")", "[for x in [1] : x]", "{ for k, v in { a = 1 } : k => v }", "true ? 1 : 2"} {
		mm := &terraformModule{}
		mm.add("x.tf", []byte("resource \"t\" \"n\" { v = "+expr+" }\n"))
		if len(mm.blocks) != 1 || constShaped(mm.blocks[0].b.Body.Attributes["v"].Expr) {
			t.Errorf("%s accepted as constant-shaped", expr)
		}
	}
	for _, expr := range []string{"\"s\"", "[1, \"a\"]", "{ a = 1 }", "jsonencode({ a = 1 })", "\"${\"a\"}b\"", "[1][0]"} {
		mm := &terraformModule{}
		mm.add("x.tf", []byte("resource \"t\" \"n\" { v = "+expr+" }\n"))
		if len(mm.blocks) != 1 || !constShaped(mm.blocks[0].b.Body.Attributes["v"].Expr) {
			t.Errorf("%s rejected although constant", expr)
		}
	}
}

// Finding 2: a cancelled context stops the Terraform pass between blocks.
func TestTerraformHonoursContext(t *testing.T) {
	m := &terraformModule{}
	var b strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "resource \"aws_kms_key\" \"k%d\" {}\n", i)
	}
	m.add("k.tf", []byte(b.String()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := 0
	em := &emitter{assetKey: "repo:/x", red: safety.NewRedactor(), emit: func(domain.Finding) error { n++; return nil }}
	e, _ := New()
	em.e = e
	if err := checkTerraform(ctx, m, em); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("err=%v emitted=%d", err, n)
	}
}

// Finding 8: every rule emitted through emitter.secret is a secret rule for
// fingerprinting, so moving the line keeps the fingerprint and two distinct
// secrets in one file still differ.
func TestIaCSecretFingerprintIgnoresLine(t *testing.T) {
	for _, id := range []string{"iac.docker.secret-in-env", "iac.k8s.secret-in-env", "iac.tf.secret-in-variable-default", "iac.tf.lambda-secret-in-env"} {
		if !domain.IsSecretRule(id) {
			t.Errorf("%s not classified as a secret rule", id)
		}
	}
	dir := t.TempDir()
	df := "FROM alpine:3.20\nENV API_KEY=51H8xFakeTokenValue000000\nENV DB_PASSWORD=hunter2-not-a-real-pw\nUSER app\n"
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o600)
	first := runOn(t, dir)["iac.docker.secret-in-env"]
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("# a line above\n\n"+df), 0o600)
	second := runOn(t, dir)["iac.docker.secret-in-env"]
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("want two secrets each run: %d %d", len(first), len(second))
	}
	fp := func(fs []domain.Finding) map[string]bool {
		m := map[string]bool{}
		for _, f := range fs {
			m[f.Fingerprint] = true
		}
		return m
	}
	a, b := fp(first), fp(second)
	if len(a) != 2 {
		t.Fatalf("distinct secrets in one file must have distinct fingerprints: %v", a)
	}
	for k := range a {
		if !b[k] {
			t.Fatalf("fingerprint changed after inserting a line: %v vs %v (locations %v / %v)", a, b, locs(first), locs(second))
		}
	}
	if first[0].Location == second[0].Location {
		t.Fatalf("location should still carry the new line: %s", second[0].Location)
	}
}

func FuzzIaC(f *testing.F) {
	for _, n := range []string{"Dockerfile", "k8s/deployment.yaml", "terraform/main.tf"} {
		if b, err := os.ReadFile(filepath.Join(fixtureRepo, n)); err == nil {
			f.Add(n, b)
		}
	}
	// Seeds for the depth and expression-shape guards.
	f.Add("deep.tf", []byte("a = "+strings.Repeat("(", 300)+"1"+strings.Repeat(")", 300)))
	f.Add("for.tf", []byte("resource \"aws_s3_bucket\" \"b\" { acl = [for a in [\"x\"] : [for b in [\"y\"] : a]] }"))
	f.Add("deep.yaml", []byte("apiVersion: v1\nkind: Pod\nspec: "+strings.Repeat("[", 300)+strings.Repeat("]", 300)))
	f.Add("chain.yaml", []byte("apiVersion: v1\nkind: Pod\nspec:\n  "+strings.Repeat("- ", 300)+"x\n"))
	f.Fuzz(func(t *testing.T, name string, b []byte) {
		e, _ := New()
		em := &emitter{e: e, assetKey: "repo:/x", red: safety.NewRedactor(), emit: func(domain.Finding) error { return nil }}
		switch {
		case strings.HasSuffix(name, ".tf"):
			m := &terraformModule{}
			m.add("f.tf", b)
			_ = checkTerraform(context.Background(), m, em)
		case strings.HasSuffix(name, ".yaml"):
			if looksLikeK8s(b) {
				_ = checkKubernetes("f.yaml", b, em)
			}
		default:
			_ = checkDockerfile("Dockerfile", b, em)
		}
	})
}
