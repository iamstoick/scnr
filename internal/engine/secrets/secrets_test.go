package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

const fakeAWS = "AKIAIOSFODNN7EXAMPLE" // AWS documentation example key

func TestScanContentRules(t *testing.T) {
	cases := []struct {
		name string
		in   string
		rule string
	}{
		{"aws", `key = "` + fakeAWS + `"`, "secret.aws-access-key"},
		{"github", "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789", "secret.github-token"},
		{"gitlab", "GL=glpat-ABCDEFGHIJKLMNOPQRSTuvwx", "secret.gitlab-token"},
		{"slack", "xox" + "b-123456789012-ABCDEFGHIJKLMNOP", "secret.slack-token"},
		{"stripe", "sk_" + "live_ABCDEFGHIJKLMNOPQRSTUVWX", "secret.stripe-key"},
		{"twilio", "S" + "K0123456789abcdef0123456789abcdef", "secret.twilio-key"},
		{"google", "AIzaSyA-ABCDEFGHIJKLMNOPQRSTUVWXYZ01234", "secret.google-api-key"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "secret.private-key"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "secret.jwt"},
		{"url creds", "DATABASE_URL=postgres://app:Sup3rS3cretPw@db.internal:5432/app", "secret.url-credentials"},
		{"generic password", `password = "x9!Kq2#vLm8$Zr4w"`, "secret.generic-password"},
		{"entropy", `token = "Zk9vP2qLm8Xr4WtB7nC3jH6dF1sG5aYe"`, "secret.generic-high-entropy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := ScanContent([]byte(c.in))
			found := false
			for _, m := range ms {
				if m.Rule == c.rule {
					found = true
				}
			}
			if !found {
				t.Fatalf("rule %s not found in %v", c.rule, ms)
			}
		})
	}
}

func TestScanContentNegatives(t *testing.T) {
	inputs := []string{
		`password = "${DB_PASSWORD}"`,
		`password = "changeme"`,
		`api_key = "<your-api-key>"`,
		`sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`,
		`AKIA short`,
		`DATABASE_URL=postgres://app:${PASS}@db/app`,
		"plain text with nothing interesting at all",
	}
	for _, in := range inputs {
		if ms := ScanContent([]byte(in)); len(ms) != 0 {
			t.Errorf("%q: unexpected %v", in, ms)
		}
	}
}

func TestDedupeAndLineNumbers(t *testing.T) {
	ms := ScanContent([]byte("a\nb\nkey=" + fakeAWS + "\nagain " + fakeAWS + "\n"))
	if len(ms) != 1 || ms[0].Line != 3 {
		t.Fatalf("want one match on line 3, got %+v", ms)
	}
}

func TestEngineRedactsBeforeEvidence(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o755)
	os.WriteFile(filepath.Join(dir, "node_modules", "x", "k.js"), []byte("AKIAZZZZZZZZZZZZZZZZ"), 0o600)
	os.WriteFile(filepath.Join(dir, "conf.py"), []byte("AWS_KEY = '"+fakeAWS+"'\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "bin.dat"), append([]byte{0, 1, 2}, []byte(fakeAWS)...), 0o600)
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tgt := domain.Target{Type: domain.TargetPath, Value: dir}
	if !e.Supports(tgt) || e.Supports(domain.Target{Type: domain.TargetHost}) {
		t.Fatal("Supports")
	}
	// The engine refuses to run without the per-install key: an unkeyed
	// digest would let a report holder confirm guessed secrets offline.
	if err := e.Run(context.Background(), tgt, engine.Options{Redactor: safety.NewRedactor()}, func(domain.Finding) error { return nil }); err == nil {
		t.Fatal("Run without SecretKey must fail")
	}
	key := []byte("test-key-test-key-test-key-test!")
	opts := engine.Options{Redactor: safety.NewRedactor(), SecretKey: key}
	var out []domain.Finding
	err = e.Run(context.Background(), tgt, opts, func(f domain.Finding) error {
		out = append(out, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 finding (node_modules and binaries skipped), got %d: %+v", len(out), out)
	}
	f := out[0]
	if f.RuleID != "secret.aws-access-key" || f.Severity != domain.Critical || f.Confidence != domain.Firm {
		t.Fatalf("finding = %+v", f)
	}
	if len(f.Evidence) != 1 {
		t.Fatal("evidence missing")
	}
	ev := f.Evidence[0]
	if !strings.HasPrefix(ev.Redacted, "AKIA") || !strings.HasSuffix(ev.Redacted, "E") || strings.Contains(ev.Redacted, "IOSFODNN") {
		t.Fatalf("redacted = %q", ev.Redacted)
	}
	if ev.Hash != safety.SecretHash(key, fakeAWS) || ev.Hash == domain.SHA256Hex(fakeAWS) {
		t.Fatalf("hash = %q (must be keyed)", ev.Hash)
	}
	if ev.Location != "conf.py:1" || !strings.HasPrefix(f.Location, "conf.py:1#") {
		t.Fatalf("locations: %q %q", ev.Location, f.Location)
	}
	// The raw key must not appear anywhere in the finding.
	for _, s := range []string{f.Title, f.WhatItIs, f.Location, ev.Redacted, f.Fingerprint} {
		if strings.Contains(s, fakeAWS) {
			t.Fatalf("raw secret leaked into %q", s)
		}
	}
	// Moving the secret to another line keeps the fingerprint (same key).
	os.WriteFile(filepath.Join(dir, "conf.py"), []byte("# moved\n\nAWS_KEY = '"+fakeAWS+"'\n"), 0o600)
	var out2 []domain.Finding
	e.Run(context.Background(), tgt, opts, func(f domain.Finding) error { out2 = append(out2, f); return nil })
	if len(out2) != 1 || out2[0].Fingerprint != f.Fingerprint {
		t.Fatalf("fingerprint changed when secret moved: %+v", out2)
	}
	// A different install (key) yields a different fingerprint.
	var out3 []domain.Finding
	e.Run(context.Background(), tgt, engine.Options{SecretKey: []byte("other-key-other-key-other-key-o!")}, func(f domain.Finding) error { out3 = append(out3, f); return nil })
	if len(out3) != 1 || out3[0].Fingerprint == f.Fingerprint {
		t.Fatalf("fingerprint must depend on the install key: %+v", out3)
	}
}

func TestEntropy(t *testing.T) {
	if entropy("aaaaaaaa") != 0 {
		t.Fatal("constant string entropy should be 0")
	}
	if entropy("Zk9vP2qLm8Xr4WtB7nC3jH6dF1sG5aYe") < 4.0 {
		t.Fatal("random string entropy should be >= 4")
	}
}

func FuzzScanContent(f *testing.F) {
	f.Add([]byte("password = 'abc'"))
	f.Add([]byte(fakeAWS))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, m := range ScanContent(b) {
			if m.Line < 1 || m.Raw == "" {
				t.Fatalf("bad match %+v", m)
			}
		}
	})
}
