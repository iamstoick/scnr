package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/adapter/adaptertest"
	"github.com/iamstoick/scnr/internal/jsonschema"
)

// copyToFlag returns a fake-binary body that copies file to the path given
// after flag (builtins only).
func copyToFlag(flag, file string) string {
	return `OUT2=''; prev=''; for a in "$@"; do if [ "$prev" = "` + flag + `" ]; then OUT2="$a"; fi; prev="$a"; done; : > "$OUT2"; while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >> "$OUT2"; done < '` + file + `'`
}

// Acceptance 3.4: the same CVE from native SCA, trivy and grype collapses
// to one finding with all three engines listed in its evidence.
func TestCrossToolSCADedupe(t *testing.T) {
	h := newHarness(t)
	osv := fakeOSV(t)
	defer osv.Close()
	h.app.OSVBase = osv.URL
	repo := fixtureRepo(t)
	trivyFixture := filepath.Join(adaptertest.FixtureDir(t, "trivy", "0.58.0"), "results.json")
	adaptertest.Install(t, "trivy", "--version", "Version: 0.58.0", copyToFlag("--output", trivyFixture))
	grypeFixture := filepath.Join(adaptertest.FixtureDir(t, "grype", "0.80.0"), "results.json")
	// Install prepends to PATH, so both fakes stay visible.
	adaptertest.Install(t, "grype", "--version", "grype 0.80.0", copyToFlag("--file", grypeFixture))
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--engines", "sca,adapter:trivy,adapter:grype")
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	for _, name := range []string{"adapter:trivy", "adapter:grype", "sca"} {
		if st, _ := engineStatus(scan, name); st != "ok" {
			t.Fatalf("%s status %q", name, st)
		}
	}
	if _, v := engineStatus(scan, "adapter:trivy"); v != "0.58.0" {
		t.Fatalf("trivy version %q", v)
	}
	ids := ruleIDs(findings)
	const shared = "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"
	if ids[shared] != 1 {
		t.Fatalf("want exactly one shared finding, got %d: %v", ids[shared], ids)
	}
	for _, f := range findings {
		if f["rule_id"] != shared {
			continue
		}
		ev := f["evidence"].([]any)
		labels := map[string]bool{}
		for _, e := range ev {
			r := e.(map[string]any)["redacted"].(string)
			labels[strings.SplitN(r, ":", 2)[0]] = true
		}
		if len(ev) != 3 || !labels["sca"] || !labels["trivy"] || !labels["grype"] {
			t.Fatalf("evidence should list three engines: %v", ev)
		}
		if f["location"] != "package-lock.json" {
			t.Fatalf("location %v", f["location"])
		}
	}
	// trivy's extra results (misconfig, secret) arrive too; the secret match is redacted.
	if ids["trivy:DS002"] != 1 || ids["secret:aws-access-key-id"] != 1 {
		t.Fatalf("%v", ids)
	}
	grepTree(t, out, "AKIAIOSFODNN7EXAMPLE")
	grepTree(t, h.home, "AKIAIOSFODNN7EXAMPLE")

	// Second scan with the tools gone: sca alone still sees the finding, the
	// adapters are skipped, and nothing is marked fixed (their engine did not
	// run ok).
	adaptertest.Hide(t)
	code = h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", out, "--engines", "sca,adapter:trivy,adapter:grype")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	scan, findings = readJSONReport(t, out)
	if scan["partial"] != true {
		t.Fatal("missing tools must mark the scan partial")
	}
	for _, f := range findings {
		if f["rule_id"] == "trivy:DS002" && f["status"] != "open" {
			t.Fatalf("trivy finding must stay open while trivy is skipped: %v", f["status"])
		}
	}
}

// scnr sbom writes a CycloneDX 1.5 document that validates against the
// schema, works for a local image archive, refuses registry references, and
// is audited.
func TestSBOMCommand(t *testing.T) {
	h := newHarness(t)
	repo, _ := filepath.Abs("../../testdata/phase3-repo")
	out := filepath.Join(t.TempDir(), "bom.json")
	if code := h.run(t, "sbom", repo, "--out", out); code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	v, err := jsonschema.Load("../../testdata/cyclonedx/bom-1.5.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if errs, err := v.Validate(b); err != nil || len(errs) > 0 {
		t.Fatalf("%v %v", errs, err)
	}
	var bom struct {
		Components []struct {
			Purl string `json:"purl"`
		} `json:"components"`
	}
	json.Unmarshal(b, &bom)
	if len(bom.Components) < 20 {
		t.Fatalf("%d components", len(bom.Components))
	}
	// Image archive on stdout.
	tarPath, _ := filepath.Abs("../../testdata/image/alpine-small.tar")
	if code := h.run(t, "sbom", tarPath); code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if errs, _ := v.Validate(h.stdout.Bytes()); len(errs) > 0 || !strings.Contains(h.stdout.String(), "pkg:apk/alpine/musl@1.2.4-r1") {
		t.Fatalf("%v\n%s", errs, h.stdout.String())
	}
	// Registry reference and bad format are usage errors.
	if code := h.run(t, "sbom", "alpine:3.18"); code != ExitUsage || !strings.Contains(h.stderr.String(), "docker save") {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if code := h.run(t, "sbom", repo, "--format", "spdx"); code != ExitUsage {
		t.Fatalf("exit %d", code)
	}
	// Finding 10: --out never follows a symlink or truncates a non-regular
	// file; the usage error is reported and the target is untouched.
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	link := filepath.Join(t.TempDir(), "bom.json")
	os.Symlink(victim, link)
	if code := h.run(t, "sbom", repo, "--out", link); code != ExitUsage || !strings.Contains(h.stderr.String(), "symbolic link") {
		t.Fatalf("symlinked --out: exit %d: %s", code, h.stderr.String())
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("symlink target overwritten: %q", b)
	}
	if code := h.run(t, "sbom", repo, "--out", t.TempDir()); code != ExitUsage {
		t.Fatalf("--out on a directory: exit %d: %s", code, h.stderr.String())
	}
	n := 0
	for _, r := range h.auditRows(t) {
		if r.Action == "sbom" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("sbom audit rows %d", n)
	}
}

// A local image archive scans through the native image engine; the lockfile
// inside it is looked up like a repo lockfile and the asset is the image.
func TestScanImageArchive(t *testing.T) {
	h := newHarness(t)
	osv := fakeOSV(t)
	defer osv.Close()
	h.app.OSVBase = osv.URL
	tarPath, _ := filepath.Abs("../../testdata/image/alpine-small.tar")
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", tarPath, "--ack-authorized", "--non-interactive", "--out", out, "--skip-engines", "adapter:trivy,adapter:grype")
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	if st, _ := engineStatus(scan, "image"); st != "ok" {
		t.Fatalf("image status %q (%v)", st, scan["engines"])
	}
	if scan["partial"] != false {
		t.Fatalf("partial: %v", scan["engines"])
	}
	ids := ruleIDs(findings)
	if ids["sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"] != 1 {
		t.Fatalf("%v", ids)
	}
	for _, f := range findings {
		if f["asset_key"] != "image:"+tarPath || f["engine"] != "image" || f["location"] != "app/package-lock.json" {
			t.Fatalf("%v", f)
		}
	}
	// The whited-out secret from the base layer is nowhere on disk.
	grepTree(t, out, "AKIAIOSFODNN7EXAMPLE")
	grepTree(t, h.home, "AKIAIOSFODNN7EXAMPLE")
	// A registry reference is accepted as a target but every image engine skips it.
	code = h.run(t, "scan", "alpine:3.18", "--type", "image", "--ack-authorized", "--non-interactive", "--out", out)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	scan, _ = readJSONReport(t, out)
	if st, _ := engineStatus(scan, "image"); !strings.HasPrefix(st, "skipped") || !strings.Contains(st, "docker save") {
		t.Fatalf("image status %q", st)
	}
	// The tool adapters are absent here (skipped for that reason first); with
	// fake tools installed they skip with the same docker-save hint.
	adaptertest.Install(t, "trivy", "--version", "Version: 0.58.0", "exit 1")
	adaptertest.Install(t, "grype", "--version", "grype 0.80.0", "exit 1")
	code = h.run(t, "scan", "alpine:3.18", "--type", "image", "--ack-authorized", "--non-interactive", "--out", out)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	scan, _ = readJSONReport(t, out)
	for _, name := range []string{"image", "adapter:trivy", "adapter:grype"} {
		if st, _ := engineStatus(scan, name); !strings.HasPrefix(st, "skipped") || !strings.Contains(st, "docker save") {
			t.Fatalf("%s status %q", name, st)
		}
	}
}

// IaC and codecheck run on repo scans and their secrets are redacted.
func TestScanRepoIaCAndCodecheck(t *testing.T) {
	h := newHarness(t)
	repo, _ := filepath.Abs("../../testdata/phase3-repo")
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--offline", "--out", out, "--engines", "iac,codecheck,secrets")
	if code != ExitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	_, findings := readJSONReport(t, out)
	ids := ruleIDs(findings)
	for _, want := range []string{"iac.docker.no-user", "iac.k8s.privileged", "iac.tf.s3-public-acl", "iac.tf.sg-open-ssh", "iac.tf.iam-wildcard-action", "iac.tf.secret-in-variable-default", "code.tls-verify-disabled", "code.sql-concat"} {
		if ids[want] == 0 {
			t.Errorf("missing %s", want)
		}
	}
	for _, f := range findings {
		if strings.HasPrefix(f["rule_id"].(string), "code.") && f["confidence"] != float64(0) { // domain.Tentative
			t.Fatalf("codecheck finding not tentative: %v", f)
		}
	}
	grepTree(t, out, "hunter2-not-a-real-pw")
	grepTree(t, h.home, "hunter2-not-a-real-pw")
	grepTree(t, out, "51H8xFakeTokenValue000000")
}
