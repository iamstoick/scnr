package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gerald/scnr/internal/vulndb/vulndbtest"
)

// keygenAndTrust runs `db keygen`, writes a scnr.yaml that acknowledges
// authorisation and trusts the new key, and returns the key path.
func keygenAndTrust(t *testing.T, h *harness) string {
	t.Helper()
	keyPath := filepath.Join(h.home, "bundle-signing.key")
	if code := h.run(t, "db", "keygen"); code != ExitOK {
		t.Fatalf("keygen: %d %s", code, h.stderr.String())
	}
	st, err := os.Stat(keyPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", err, st)
	}
	var pub string
	for _, line := range strings.Split(h.stdout.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ed25519:") {
			pub = strings.TrimSpace(line)
		}
	}
	if pub == "" || !strings.Contains(h.stdout.String(), "Fingerprint:") {
		t.Fatalf("keygen output: %s", h.stdout.String())
	}
	if code := h.run(t, "db", "keygen"); code == ExitOK {
		t.Fatal("keygen overwrote an existing key")
	}
	cfg := filepath.Join(h.home, "scnr.yaml")
	os.WriteFile(cfg, []byte("authorization: {acknowledged: true, by: t}\nscope:\n  allow: []\n  deny: []\nvulndb:\n  trusted_keys: [\""+pub+"\"]\n"), 0o600)
	h.app.ConfigPath = cfg
	return keyPath
}

// buildBundle runs `db bundle build` against the recorded GCS fixture and
// returns the bundle path. signKey may be empty (unsigned).
func buildBundle(t *testing.T, h *harness, signKey string) string {
	t.Helper()
	srv := vulndbtest.GCSServer(t, map[string][]byte{"npm": vulndbtest.Zip(t, vulndbtest.LodashVuln())}, "")
	h.app.BundleBase = srv.URL
	out := t.TempDir()
	args := []string{"db", "bundle", "build", "--out", out, "--ecosystems", "npm"}
	if signKey != "" {
		args = append(args, "--sign-key", signKey)
	}
	if code := h.run(t, args...); code != ExitOK {
		t.Fatalf("bundle build: %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	matches, _ := filepath.Glob(filepath.Join(out, "scnr-osv-*.tar.gz"))
	if len(matches) != 1 {
		t.Fatalf("bundle not written: %v", matches)
	}
	return matches[0]
}

// Acceptance 4a.1-3: keygen, build, verify, load, status, offline scan with
// the same findings as the online run; tampered and foreign-signed bundles
// are refused.
func TestOfflineBundleEndToEnd(t *testing.T) {
	h := newHarness(t)
	keyPath := keygenAndTrust(t, h)
	bundle := buildBundle(t, h, keyPath)
	if !strings.Contains(h.stdout.String(), "Signer:") || !strings.Contains(h.stdout.String(), "affected/npm.jsonl") {
		t.Fatalf("build output: %s", h.stdout.String())
	}

	if code := h.run(t, "db", "bundle", "verify", bundle); code != ExitOK {
		t.Fatalf("verify: %d %s", code, h.stderr.String())
	}
	out := h.stdout.String()
	if !strings.Contains(out, "ecosystems: npm") || !strings.Contains(out, "1 records") || !strings.Contains(out, "Signer: ") || strings.Contains(out, "UNSIGNED") {
		t.Fatalf("verify output: %s", out)
	}
	if code := h.run(t, "db", "status"); code != ExitOK || !strings.Contains(h.stdout.String(), "osv-offline not loaded") {
		t.Fatalf("status before load: %s", h.stdout.String())
	}

	// Offline scan before the load: sca is skipped as before.
	repo := fixtureRepo(t)
	outDir := filepath.Join(t.TempDir(), "out")
	if code := h.run(t, "scan", repo, "--offline", "--ack-authorized", "--non-interactive", "--out", outDir, "--engines", "sca"); code != ExitOK {
		t.Fatalf("offline scan before load: %d %s", code, h.stderr.String())
	}
	scan, _ := readJSONReport(t, outDir)
	if st, _ := engineStatus(scan, "sca"); st != "skipped: offline" {
		t.Fatalf("sca before load: %q", st)
	}

	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--non-interactive"); code != ExitOK {
		t.Fatalf("load: %d %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "1 affected records") {
		t.Fatalf("load output: %s", h.stdout.String())
	}
	if code := h.run(t, "db", "status"); code != ExitOK || !strings.Contains(h.stdout.String(), "osv-offline 1 rows") {
		t.Fatalf("status: %s", h.stdout.String())
	}
	if code := h.run(t, "doctor"); code != ExitOK || !strings.Contains(h.stdout.String(), "vulndb osv-offline") || strings.Contains(h.stdout.String(), "osv-offline MISSING") {
		t.Fatalf("doctor: %s", h.stdout.String())
	}

	// Offline scan now matches the online fixture run.
	offDir := filepath.Join(t.TempDir(), "off")
	if code := h.run(t, "scan", repo, "--offline", "--ack-authorized", "--non-interactive", "--out", offDir, "--engines", "sca"); code != ExitOK {
		t.Fatalf("offline scan: %d %s", code, h.stderr.String())
	}
	offScan, offFindings := readJSONReport(t, offDir)
	if st, _ := engineStatus(offScan, "sca"); st != "ok" {
		t.Fatalf("sca offline status %q", st)
	}
	osv := fakeOSV(t)
	defer osv.Close()
	h.app.OSVBase = osv.URL
	onDir := filepath.Join(t.TempDir(), "on")
	if code := h.run(t, "scan", repo, "--ack-authorized", "--non-interactive", "--out", onDir, "--engines", "sca"); code != ExitOK {
		t.Fatalf("online scan: %d %s", code, h.stderr.String())
	}
	_, onFindings := readJSONReport(t, onDir)
	on, off := scaRules(onFindings), scaRules(offFindings)
	if len(on) == 0 || strings.Join(on, ",") != strings.Join(off, ",") {
		t.Fatalf("online %v != offline %v", on, off)
	}
	if off[0] != "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20" {
		t.Fatalf("rules: %v", off)
	}

	// Audit: the load recorded bundle hash, signer and ecosystems.
	var loads int
	for _, r := range h.auditRows(t) {
		if r.Action != "db_update" {
			continue
		}
		var d map[string]any
		json.Unmarshal(r.Detail, &d)
		if d["signer"] != "" && d["ok"] == true {
			loads++
			if len(d["bundle"].(string)) != 64 || d["unsigned"] != false || d["records"].(float64) != 1 {
				t.Fatalf("db_update detail: %s", r.Detail)
			}
		}
	}
	if loads != 1 {
		t.Fatalf("db_update audit rows for the load: %d", loads)
	}

	// Tampered bundle: a flipped byte breaks the gzip stream or a digest.
	tampered := filepath.Join(t.TempDir(), "tampered.tar.gz")
	b, _ := os.ReadFile(bundle)
	b[len(b)/2] ^= 0xff
	os.WriteFile(tampered, b, 0o600)
	if code := h.run(t, "db", "bundle", "verify", tampered); code == ExitOK {
		t.Fatal("tampered bundle verified")
	}
	if code := h.run(t, "db", "update", "--offline-bundle", tampered, "--non-interactive"); code == ExitOK {
		t.Fatal("tampered bundle loaded")
	}
	if code := h.run(t, "db", "status"); !strings.Contains(h.stdout.String(), "osv-offline 1 rows") {
		t.Fatalf("tampered load changed the store (%d): %s", code, h.stdout.String())
	}

	// Signed by a key that is not trusted: exit 3, E_BUNDLE_UNTRUSTED, audited.
	otherHome := newHarness(t)
	otherKey := keygenAndTrust(t, otherHome)
	foreign := buildBundle(t, otherHome, otherKey)
	if code := h.run(t, "db", "update", "--offline-bundle", foreign, "--non-interactive"); code != ExitRefused || !strings.Contains(h.stderr.String(), "E_BUNDLE_UNTRUSTED") {
		t.Fatalf("foreign-signed: %d %s", code, h.stderr.String())
	}
	if !hasAudit(t, h, "gate_refused", "E_BUNDLE_UNTRUSTED") {
		t.Fatal("foreign-signed refusal not audited")
	}
}

// A6: an unsigned bundle cannot be loaded non-interactively, with or
// without --allow-unsigned; interactively it loads only with the flag and
// the acceptance is audited.
func TestUnsignedBundleRefusedNonInteractive(t *testing.T) {
	h := newHarness(t)
	keygenAndTrust(t, h)
	bundle := buildBundle(t, h, "")
	if !strings.Contains(h.stderr.String(), "UNSIGNED") {
		t.Fatalf("build should warn about an unsigned bundle: %s", h.stderr.String())
	}
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--allow-unsigned", "--non-interactive"); code != ExitRefused || !strings.Contains(h.stderr.String(), "E_BUNDLE_UNTRUSTED") {
		t.Fatalf("--allow-unsigned --non-interactive: %d %s", code, h.stderr.String())
	}
	// No TTY counts as non-interactive even without the flag.
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--allow-unsigned"); code != ExitRefused {
		t.Fatalf("--allow-unsigned without a TTY: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--non-interactive"); code != ExitRefused || !strings.Contains(h.stderr.String(), "unsigned") {
		t.Fatalf("unsigned without flag: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "db", "bundle", "verify", bundle); code != ExitRefused {
		t.Fatalf("verify unsigned: %d", code)
	}
	refusals := 0
	for _, r := range h.auditRows(t) {
		if r.Action == "gate_refused" && strings.Contains(string(r.Detail), "E_BUNDLE_UNTRUSTED") {
			refusals++
		}
	}
	if refusals != 3 {
		t.Fatalf("want 3 gate_refused rows, got %d", refusals)
	}
	if code := h.run(t, "db", "status"); !strings.Contains(h.stdout.String(), "osv-offline not loaded") {
		t.Fatalf("store changed (%d): %s", code, h.stdout.String())
	}

	// Interactive with the flag: accepted and audited as unsigned.
	h.app.IsTTY = true
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--allow-unsigned"); code != ExitOK || !strings.Contains(h.stdout.String(), "UNSIGNED") {
		t.Fatalf("interactive --allow-unsigned: %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if !hasAudit(t, h, "db_update", `"unsigned":true`) {
		t.Fatal("unsigned acceptance not audited")
	}
	if code := h.run(t, "db", "bundle", "verify", bundle, "--allow-unsigned"); code != ExitOK || !strings.Contains(h.stdout.String(), "Signer: none") {
		t.Fatalf("verify --allow-unsigned: %d %s", code, h.stdout.String())
	}
}

// A bundle older than the loaded osv-offline data is a downgrade: refused
// and audited; --allow-downgrade is gated like --allow-unsigned (TTY only,
// never with --non-interactive) and the acceptance is audited.
func TestBundleDowngradeGate(t *testing.T) {
	h := newHarness(t)
	keyPath := keygenAndTrust(t, h)
	bundle := buildBundle(t, h, keyPath) // created_at = today
	// Pretend a newer bundle was loaded earlier.
	st := h.store(t)
	load, err := st.BeginOfflineLoad(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := load.Commit(context.Background(), "2999-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--non-interactive"); code != ExitRefused || !strings.Contains(h.stderr.String(), "E_BUNDLE_DOWNGRADE") {
		t.Fatalf("older bundle: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--allow-downgrade", "--non-interactive"); code != ExitRefused || !strings.Contains(h.stderr.String(), "interactive session") {
		t.Fatalf("--allow-downgrade --non-interactive: %d %s", code, h.stderr.String())
	}
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--allow-downgrade"); code != ExitRefused {
		t.Fatalf("--allow-downgrade without a TTY: %d %s", code, h.stderr.String())
	}
	refusals := 0
	for _, r := range h.auditRows(t) {
		if r.Action == "gate_refused" && strings.Contains(string(r.Detail), "E_BUNDLE_DOWNGRADE") {
			refusals++
		}
	}
	if refusals != 3 {
		t.Fatalf("want 3 gate_refused rows, got %d", refusals)
	}
	if code := h.run(t, "db", "status"); code != ExitOK || !strings.Contains(h.stdout.String(), `version "2999-01-01T00:00:00Z"`) {
		t.Fatalf("store changed by refused downgrade (%d): %s", code, h.stdout.String())
	}
	h.app.IsTTY = true
	if code := h.run(t, "db", "update", "--offline-bundle", bundle, "--allow-downgrade"); code != ExitOK || !strings.Contains(h.stdout.String(), "allow-downgrade") {
		t.Fatalf("interactive --allow-downgrade: %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if !hasAudit(t, h, "db_update", `"downgrade":true`) {
		t.Fatal("downgrade acceptance not audited")
	}
	if code := h.run(t, "db", "status"); code != ExitOK || strings.Contains(h.stdout.String(), "2999-01-01") {
		t.Fatalf("downgrade not applied: %s", h.stdout.String())
	}
}

func scaRules(findings []map[string]any) []string {
	var out []string
	for _, f := range findings {
		if id := f["rule_id"].(string); strings.HasPrefix(id, "sca.osv.") {
			out = append(out, id)
		}
	}
	return out
}

func hasAudit(t *testing.T, h *harness, action, needle string) bool {
	t.Helper()
	for _, r := range h.auditRows(t) {
		if r.Action == action && strings.Contains(string(r.Detail), needle) {
			return true
		}
	}
	return false
}
