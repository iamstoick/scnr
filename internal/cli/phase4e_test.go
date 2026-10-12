package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/vulndb"
)

func writePluginTestConfig(t *testing.T, h *harness, trustedKey string) {
	t.Helper()
	cfg := filepath.Join(h.home, "scnr.yaml")
	body := "authorization: {acknowledged: true, by: t}\nplugins:\n  trusted_keys:\n    - \"" + trustedKey + "\"\n  sandbox: best-effort\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	h.app.ConfigPath = cfg
}

// stageCLIPlugin writes an installable plugin tree: a shell-script
// payload emitting one finding plus an unsigned manifest.
func stageCLIPlugin(t *testing.T, dir string) {
	t.Helper()
	script := "#!/bin/sh\n/bin/cat > /dev/null\nprintf '%s\\n' '{\"rule\":\"cli-rule\",\"location\":\"app.js\",\"confidence\":\"firm\"}'\n"
	manifest := `{"protocol":1,"name":"cliplug","version":"1.0.0",` +
		`"description":"cli test plugin","homepage":"https://example.com/cliplug",` +
		`"supports":["path"],"safety":"safe",` +
		`"capabilities":{"network":"none","filesystem":"target-readonly"},` +
		`"rules":[{"id":"cli-rule","title":"CLI rule","severity":"medium","what":"w","why":"y","fix":"f"}]}` + "\n"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scnr-plugin-cliplug"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

// Full CLI loop: sign, install, list, show, verify, scan with the
// plugin selected, drift, remove.
func TestPluginCLILoop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake plugin is a shell script")
	}
	h := newHarness(t)
	seed, pub, err := vulndb.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	writePluginTestConfig(t, h, vulndb.FormatTrustedKey(pub))

	stage := filepath.Join(t.TempDir(), "stage")
	stageCLIPlugin(t, stage)
	keyFile := filepath.Join(t.TempDir(), "sign.key")
	if err := vulndb.WriteKeyFile(keyFile, seed); err != nil {
		t.Fatal(err)
	}
	if code := h.run(t, "plugin", "sign", stage, "--key", keyFile); code != ExitOK {
		t.Fatalf("sign exit %d: %s", code, h.stderr.String())
	}
	if code := h.run(t, "plugin", "install", stage); code != ExitOK {
		t.Fatalf("install exit %d: %s", code, h.stderr.String())
	}
	if code := h.run(t, "plugin", "list"); code != ExitOK || !strings.Contains(h.stdout.String(), "* cliplug@1.0.0") {
		t.Fatalf("list exit %d: %s", code, h.stdout.String())
	}
	if code := h.run(t, "plugin", "show", "cliplug"); code != ExitOK || !strings.Contains(h.stdout.String(), "integrity: ok") {
		t.Fatalf("show exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run(t, "plugin", "verify"); code != ExitOK {
		t.Fatalf("verify exit %d: %s", code, h.stderr.String())
	}

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.js"), []byte("var x = 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", target, "--ack-authorized", "--non-interactive",
		"--out", out, "--engines", "plugin:cliplug", "--offline")
	if code != ExitOK {
		t.Fatalf("scan exit %d: %s", code, h.stderr.String())
	}
	scan, findings := readJSONReport(t, out)
	if ruleIDs(findings)["plugin.cliplug.cli-rule"] != 1 {
		t.Fatalf("findings = %v", ruleIDs(findings))
	}
	var engineStatus string
	for _, e := range scan["engines"].([]any) {
		em := e.(map[string]any)
		if em["name"] == "plugin:cliplug" {
			engineStatus, _ = em["status"].(string)
		}
	}
	if engineStatus != "ok" {
		t.Fatalf("plugin engine status = %q (scan %+v)", engineStatus, scan["engines"])
	}
	var sawInstall bool
	for _, row := range h.auditRows(t) {
		if row.Action == "plugin_install" {
			sawInstall = true
		}
	}
	if !sawInstall {
		t.Fatal("no plugin_install audit row")
	}

	// Drift: corrupt the installed binary, verify must fail loudly.
	binPath := filepath.Join(h.home, "plugins", "cliplug", "1.0.0", "scnr-plugin-cliplug")
	f, err := os.OpenFile(binPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("x"))
	_ = f.Close()
	if code := h.run(t, "plugin", "verify"); code == ExitOK || !strings.Contains(h.stdout.String(), "DRIFT") {
		t.Fatalf("verify exit %d: %s", code, h.stdout.String())
	}

	if code := h.run(t, "plugin", "remove", "cliplug"); code != ExitOK {
		t.Fatalf("remove exit %d: %s", code, h.stderr.String())
	}
	if code := h.run(t, "plugin", "list"); code != ExitOK || !strings.Contains(h.stdout.String(), "no plugins installed") {
		t.Fatalf("list exit %d: %s", code, h.stdout.String())
	}
}

// Unknown engines are still rejected, and plugin: names that are not
// installed do not phantom-match.
func TestScanUnknownPluginEngine(t *testing.T) {
	h := newHarness(t)
	writePluginTestConfig(t, h, "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	out := filepath.Join(t.TempDir(), "out")
	code := h.run(t, "scan", t.TempDir(), "--ack-authorized", "--non-interactive",
		"--out", out, "--engines", "plugin:ghost", "--offline")
	if code == ExitOK {
		t.Fatal("unknown plugin engine accepted")
	}
}

// Doctor reports plugin integrity and the sandbox wrapper state.
func TestDoctorPluginChecks(t *testing.T) {
	h := newHarness(t)
	if code := h.run(t, "doctor"); code != ExitOK {
		t.Fatalf("doctor exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "plugins") {
		t.Fatalf("no plugins section:\n%s", h.stdout.String())
	}
}
