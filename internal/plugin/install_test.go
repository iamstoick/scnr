package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testBinary = []byte("#!/bin/sh\necho fake-plugin\n")

// stagePlugin writes a valid plugin directory: manifest.json plus the
// payload. mutate adjusts the manifest map before binary_sha256 is
// stamped. It returns the exact manifest bytes written.
func stagePlugin(t *testing.T, dir, name, version string, bin []byte, mutate func(m map[string]any)) []byte {
	t.Helper()
	if bin == nil {
		bin = testBinary
	}
	sum := sha256.Sum256(bin)
	m := map[string]any{
		"protocol": 1, "name": name, "version": version,
		"description": "test plugin " + name,
		"homepage":    "https://example.com/" + name,
		"supports":    []string{"path"},
		"safety":      "safe",
		"capabilities": map[string]any{
			"network": "none", "filesystem": "target-readonly",
		},
		"binary_sha256": hex.EncodeToString(sum[:]),
		"rules": []any{map[string]any{
			"id": "ok-rule", "title": "Ok rule", "severity": "low",
			"what": "what", "why": "why", "fix": "fix",
		}},
	}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BinaryName(name)), bin, 0o700); err != nil {
		t.Fatal(err)
	}
	return raw
}

// signStage writes a manifest.sig over the staged manifest bytes.
func signStage(t *testing.T, dir string, manifest []byte, priv ed25519.PrivateKey) {
	t.Helper()
	sig := ed25519.Sign(priv, manifest)
	body := base64.StdEncoding.EncodeToString(sig) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func installOpts(home string, pubs ...ed25519.PublicKey) InstallOptions {
	return InstallOptions{
		Home: home, RequireSignature: true, TrustedKeys: pubs,
		Stdout: io.Discard, InstalledBy: "test",
	}
}

// E1: a valid signature from a trusted key installs; anything else
// refuses. The signature covers the exact manifest bytes: one flipped
// letter breaks it.
func TestInstallSignature(t *testing.T) {
	pub, priv := testKey(t)
	otherPub, _ := testKey(t)

	t.Run("valid", func(t *testing.T) {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "sigok", "1.0.0", nil, nil)
		signStage(t, stage, raw, priv)
		entry, err := Install(stage, installOpts(t.TempDir(), pub))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(entry.PublisherKey, "ed25519:") {
			t.Fatalf("publisher key = %q", entry.PublisherKey)
		}
	})

	t.Run("tampered-manifest", func(t *testing.T) {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "sigtamper", "1.0.0", nil, nil)
		signStage(t, stage, raw, priv)
		bad := bytes.Replace(raw, []byte("test plugin"), []byte("tast plugin"), 1)
		if err := os.WriteFile(filepath.Join(stage, "manifest.json"), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(stage, installOpts(t.TempDir(), pub)); err == nil {
			t.Fatal("tampered manifest installed")
		}
	})

	t.Run("untrusted-key", func(t *testing.T) {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "siguntrust", "1.0.0", nil, nil)
		signStage(t, stage, raw, priv)
		if _, err := Install(stage, installOpts(t.TempDir(), otherPub)); err == nil {
			t.Fatal("wrong-key signature installed")
		}
	})

	t.Run("no-trusted-keys", func(t *testing.T) {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "signokeys", "1.0.0", nil, nil)
		signStage(t, stage, raw, priv)
		_, err := Install(stage, installOpts(t.TempDir()))
		if err == nil || !strings.Contains(err.Error(), "trusted_keys") {
			t.Fatalf("signed plugin without configured keys installed: %v", err)
		}
	})

	t.Run("missing-signature-required", func(t *testing.T) {
		stage := t.TempDir()
		stagePlugin(t, stage, "signosig", "1.0.0", nil, nil)
		if _, err := Install(stage, installOpts(t.TempDir(), pub)); err == nil {
			t.Fatal("unsigned plugin installed with require_signature")
		}
	})

	t.Run("payload-mismatch", func(t *testing.T) {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "sigpayload", "1.0.0", nil, nil)
		signStage(t, stage, raw, priv)
		if err := os.WriteFile(filepath.Join(stage, BinaryName("sigpayload")), []byte("swapped"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(stage, installOpts(t.TempDir(), pub)); err == nil {
			t.Fatal("payload not matching binary_sha256 installed")
		}
	})
}

// E2: any drift of the installed binary or manifest from the lock is an
// integrity failure.
func TestVerifyDrift(t *testing.T) {
	pub, priv := testKey(t)
	home := t.TempDir()
	stage := t.TempDir()
	raw := stagePlugin(t, stage, "drift", "1.0.0", nil, nil)
	signStage(t, stage, raw, priv)
	entry, err := Install(stage, installOpts(home, pub))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(home, *entry); err != nil {
		t.Fatalf("fresh install does not verify: %v", err)
	}
	binPath := BinaryPath(home, *entry)
	manPath := ManifestPath(home, *entry)
	origBin, _ := os.ReadFile(binPath)

	f, err := os.OpenFile(binPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("x"))
	_ = f.Close()
	if err := Verify(home, *entry); err == nil || !strings.Contains(err.Error(), "binary hash mismatch") {
		t.Fatalf("swapped binary not detected: %v", err)
	}
	if err := os.WriteFile(binPath, origBin, 0o700); err != nil {
		t.Fatal(err)
	}
	mf, err := os.OpenFile(manPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = mf.Write([]byte(" "))
	_ = mf.Close()
	if err := Verify(home, *entry); err == nil || !strings.Contains(err.Error(), "manifest drift") {
		t.Fatalf("edited manifest not detected: %v", err)
	}
}

// E3: the unsigned ceremony needs require_signature off, an explicit
// flag, a terminal, and the typed manifest hash. Anything less refuses.
func TestInstallUnsignedCeremony(t *testing.T) {
	stage := func(t *testing.T) (dir string, confirm string) {
		dir = t.TempDir()
		raw := stagePlugin(t, dir, "unsigned", "1.0.0", nil, nil)
		sum := sha256.Sum256(raw)
		return dir, hex.EncodeToString(sum[:])[:16] + "\n"
	}
	opts := func(home, confirm string) InstallOptions {
		o := installOpts(home)
		o.RequireSignature = false
		o.AllowUnsigned = true
		o.IsTTY = true
		o.Stdin = strings.NewReader(confirm)
		return o
	}

	t.Run("correct-confirmation", func(t *testing.T) {
		dir, confirm := stage(t)
		entry, err := Install(dir, opts(t.TempDir(), confirm))
		if err != nil {
			t.Fatal(err)
		}
		if entry.PublisherKey != "unsigned" {
			t.Fatalf("publisher key = %q", entry.PublisherKey)
		}
	})

	t.Run("wrong-confirmation", func(t *testing.T) {
		dir, _ := stage(t)
		if _, err := Install(dir, opts(t.TempDir(), "0000000000000000\n")); err == nil {
			t.Fatal("wrong confirmation installed")
		}
	})

	t.Run("no-tty", func(t *testing.T) {
		dir, confirm := stage(t)
		o := opts(t.TempDir(), confirm)
		o.IsTTY = false
		if _, err := Install(dir, o); err == nil {
			t.Fatal("non-terminal unsigned install allowed")
		}
	})

	t.Run("no-flag", func(t *testing.T) {
		dir, confirm := stage(t)
		o := opts(t.TempDir(), confirm)
		o.AllowUnsigned = false
		if _, err := Install(dir, o); err == nil {
			t.Fatal("unsigned install without --allow-unsigned allowed")
		}
	})
}

// E7: reinstalling the same version refuses; downgrades need a
// terminal and an explicit "yes".
func TestInstallDowngrade(t *testing.T) {
	pub, priv := testKey(t)
	home := t.TempDir()
	install := func(version string, stdin string, isTTY bool) error {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "downgrade", version, nil, nil)
		signStage(t, stage, raw, priv)
		o := installOpts(home, pub)
		o.IsTTY = isTTY
		o.Stdin = strings.NewReader(stdin)
		_, err := Install(stage, o)
		return err
	}
	if err := install("1.1.0", "", false); err != nil {
		t.Fatal(err)
	}
	if err := install("1.1.0", "", false); err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("reinstall allowed: %v", err)
	}
	if err := install("1.0.0", "", false); err == nil || !strings.Contains(err.Error(), "older than installed") {
		t.Fatalf("non-terminal downgrade allowed: %v", err)
	}
	if err := install("1.0.0", "no\n", true); err == nil {
		t.Fatal("declined downgrade installed")
	}
	if err := install("1.0.0", "yes\n", true); err != nil {
		t.Fatalf("confirmed downgrade refused: %v", err)
	}
	l, err := LoadLock(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Find("downgrade", "latest"); !ok {
		t.Fatal("latest missing after downgrade")
	}
	if e, _ := l.Find("downgrade", "latest"); e.Version != "1.1.0" {
		t.Fatalf("latest = %s, want 1.0.0's elder 1.1.0", e.Version)
	}
}

func writeTarball(t *testing.T, path string, entries map[string][]byte, link map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range link {
		if err := tw.WriteHeader(&tar.Header{Name: name, Linkname: target, Typeflag: tar.TypeSymlink}); err != nil {
			t.Fatal(err)
		}
	}
}

// E8: tarball installs apply the bundle's tar hardening.
func TestInstallTarball(t *testing.T) {
	pub, priv := testKey(t)
	sum := sha256.Sum256(testBinary)
	manifest := map[string]any{
		"protocol": 1, "name": "tarball", "version": "1.0.0",
		"description": "tarball plugin", "homepage": "https://example.com/tarball",
		"supports": []string{"path"}, "safety": "safe",
		"capabilities":  map[string]any{"network": "none", "filesystem": "target-readonly"},
		"binary_sha256": hex.EncodeToString(sum[:]),
		"rules":         []any{map[string]any{"id": "ok-rule", "title": "Ok", "severity": "low", "what": "w", "why": "y", "fix": "f"}},
	}
	raw, _ := json.MarshalIndent(manifest, "", "  ")
	raw = append(raw, '\n')
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)) + "\n"
	bin := BinaryName("tarball")

	t.Run("valid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "p.tar.gz")
		writeTarball(t, path, map[string][]byte{"manifest.json": raw, "manifest.sig": []byte(sig), bin: testBinary}, nil)
		if _, err := Install(path, installOpts(t.TempDir(), pub)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("symlink-refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "p.tar.gz")
		writeTarball(t, path,
			map[string][]byte{"manifest.json": raw, bin: testBinary},
			map[string]string{"manifest.sig": "/etc/passwd"})
		if _, err := Install(path, installOpts(t.TempDir(), pub)); err == nil {
			t.Fatal("symlink entry installed")
		}
	})

	t.Run("unexpected-name-refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "p.tar.gz")
		writeTarball(t, path, map[string][]byte{"manifest.json": raw, bin: testBinary, "../evil.sh": []byte("x")}, nil)
		if _, err := Install(path, installOpts(t.TempDir(), pub)); err == nil {
			t.Fatal("path-traversal entry installed")
		}
	})

	t.Run("missing-payload", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "p.tar.gz")
		writeTarball(t, path, map[string][]byte{"manifest.json": raw}, nil)
		if _, err := Install(path, installOpts(t.TempDir(), pub)); err == nil {
			t.Fatal("payload-less tarball installed")
		}
	})

	t.Run("oversize-manifest", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "p.tar.gz")
		big := bytes.Repeat([]byte("x"), MaxManifestBytes+1)
		writeTarball(t, path, map[string][]byte{"manifest.json": big, bin: testBinary}, nil)
		if _, err := Install(path, installOpts(t.TempDir(), pub)); err == nil {
			t.Fatal("oversize manifest installed")
		}
	})
}

// SignManifest stamps the payload hash and signs the resulting bytes so
// a stock install verifies.
func TestSignManifestRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	seed := priv.Seed()
	dir := t.TempDir()
	// A publisher tree has no binary_sha256 yet; signing stamps it.
	stagePlugin(t, dir, "roundtrip", "2.0.0", nil, func(m map[string]any) {
		delete(m, "binary_sha256")
	})
	if err := SignManifest(dir, seed); err != nil {
		t.Fatal(err)
	}
	entry, err := Install(dir, installOpts(t.TempDir(), pub))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Version != "2.0.0" {
		t.Fatalf("version = %s", entry.Version)
	}
}

func TestRemove(t *testing.T) {
	pub, priv := testKey(t)
	home := t.TempDir()
	for _, v := range []string{"1.0.0", "1.1.0"} {
		stage := t.TempDir()
		raw := stagePlugin(t, stage, "rmplug", v, nil, nil)
		signStage(t, stage, raw, priv)
		if _, err := Install(stage, installOpts(home, pub)); err != nil {
			t.Fatal(err)
		}
	}
	var actions []string
	audit := func(action string, detail map[string]any) { actions = append(actions, action) }
	removed, err := Remove(home, "rmplug", "1.0.0", audit)
	if err != nil || len(removed) != 1 {
		t.Fatalf("remove one: %v %v", removed, err)
	}
	if _, err := os.Stat(Dir(home, "rmplug", "1.0.0")); !os.IsNotExist(err) {
		t.Fatal("version directory survives remove")
	}
	removed, err = Remove(home, "rmplug", "", audit)
	if err != nil || len(removed) != 1 {
		t.Fatalf("remove all: %v %v", removed, err)
	}
	l, err := LoadLock(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Plugins) != 0 {
		t.Fatalf("lock keeps %d entries", len(l.Plugins))
	}
	if len(actions) != 2 || actions[0] != "plugin_remove" {
		t.Fatalf("audit actions = %v", actions)
	}
	if _, err := Remove(home, "rmplug", "", nil); err == nil {
		t.Fatal("removing absent plugin succeeds")
	}
}
