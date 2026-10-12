package safety

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAuthFile(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodAuthYAML = "headers:\n  Authorization: \"Bearer test-token-12345\"\ncookies:\n  session: abcdefghijklmnop\n"

func TestLoadAuthFile(t *testing.T) {
	p := writeAuthFile(t, 0o600, goodAuthYAML)
	a, err := LoadAuthFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.HeaderCount() != 1 || a.CookieCount() != 1 {
		t.Fatalf("counts: %+v", a)
	}
	if got := a.CookieNames(); len(got) != 1 || got[0] != "session" {
		t.Fatalf("cookie names: %v", got)
	}
	if h := a.ValuesHash(); len(h) != 64 || h != a.ValuesHash() {
		t.Fatalf("hash unstable: %q", h)
	}
	// Values hash differs when values differ.
	other := MustParseForTest(t)
	if other.ValuesHash() == a.ValuesHash() {
		t.Fatal("hash collision across different values")
	}
}

func TestLoadAuthFileRefusals(t *testing.T) {
	if _, err := LoadAuthFile(writeAuthFile(t, 0o644, goodAuthYAML)); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("0644: %v", err)
	}
	if _, err := LoadAuthFile(writeAuthFile(t, 0o600, "headers:\n  X: y\nbogus: 1\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := LoadAuthFile(writeAuthFile(t, 0o600, "headers: {}\n")); err == nil {
		t.Fatal("empty material accepted")
	}
	if _, err := LoadAuthFile(writeAuthFile(t, 0o600, "headers:\n  X: \"a\\nb\"\n")); err == nil {
		t.Fatal("line break accepted")
	}
	big := "headers:\n  X: \"" + strings.Repeat("z", MaxAuthFileBytes) + "\"\n"
	if _, err := LoadAuthFile(writeAuthFile(t, 0o600, big)); err == nil {
		t.Fatal("oversize accepted")
	}
	// Symlinks are refused even when the target is compliant.
	dir := t.TempDir()
	real := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(real, []byte(goodAuthYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthFile(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
	// Refusal errors never echo values.
	_, err := LoadAuthFile(writeAuthFile(t, 0o644, goodAuthYAML))
	if strings.Contains(err.Error(), "test-token-12345") || strings.Contains(err.Error(), "abcdefghijklmnop") {
		t.Fatalf("value leaked in error: %v", err)
	}
}

func TestParseAuthLiterals(t *testing.T) {
	a, err := ParseAuthLiterals([]string{"Authorization: Bearer x", "X-Api-Key: k2"}, []string{"session=s3cr3t"})
	if err != nil {
		t.Fatal(err)
	}
	if a.HeaderCount() != 2 || a.CookieCount() != 1 {
		t.Fatalf("counts: %d %d", a.HeaderCount(), a.CookieCount())
	}
	for _, bad := range []struct {
		h, c []string
	}{{[]string{"no-colon"}, nil}, {[]string{": novalue"}, nil}, {nil, []string{"noequals"}}, {[]string{"X: a\nb"}, nil}} {
		if _, err := ParseAuthLiterals(bad.h, bad.c); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if _, err := ParseAuthLiterals(nil, nil); err == nil {
		t.Fatal("empty literals accepted")
	}
	merged := MergeAuth(a, nil)
	if merged.HeaderCount() != 2 || merged == a {
		t.Fatal("merge shares state")
	}
}

// MustParseForTest builds distinct material for hash comparison.
func MustParseForTest(t *testing.T) *AuthMaterial {
	t.Helper()
	a, err := ParseAuthLiterals([]string{"Authorization: Bearer other"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAuthMaterialNeverFormats(t *testing.T) {
	a := MustParseForTest(t)
	if strings.Contains(a.String(), "other") {
		t.Fatalf("String leaks: %s", a.String())
	}
	if _, err := json.Marshal(a); err == nil {
		t.Fatal("MarshalJSON succeeded")
	}
	if _, err := json.Marshal(map[string]any{"auth": a}); err == nil {
		t.Fatal("nested marshal succeeded")
	}
}

func TestAuthApplyOriginOnly(t *testing.T) {
	a, err := ParseAuthLiterals([]string{"Authorization: Bearer t0k3n"}, []string{"s=abc"})
	if err != nil {
		t.Fatal(err)
	}
	bound := a.WithOrigin("app.example:443")
	if a.Origin != "" {
		t.Fatal("WithOrigin mutated the receiver")
	}
	mkreq := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u, Header: http.Header{}}
	}
	// Exact origin, and the default-port spelling of it, get credentials.
	for _, raw := range []string{"https://app.example/", "https://app.example:443/x"} {
		r := mkreq(raw)
		bound.Apply(r)
		if r.Header.Get("Authorization") != "Bearer t0k3n" || r.Header.Get("Cookie") != "s=abc" {
			t.Fatalf("%s: headers %v", raw, r.Header)
		}
	}
	// Anything else gets nothing: other hosts, other ports, subdomains,
	// downgraded schemes.
	for _, raw := range []string{"https://other.example/", "https://app.example:8443/", "https://sub.app.example/", "http://app.example/"} {
		r := mkreq(raw)
		bound.Apply(r)
		if len(r.Header) != 0 {
			t.Fatalf("%s: leaked %v", raw, r.Header)
		}
	}
	// Empty origin matches nothing, and nil receivers are safe.
	r := mkreq("https://app.example/")
	a.Apply(r)
	if len(r.Header) != 0 {
		t.Fatalf("unbound material applied: %v", r.Header)
	}
	var nilAuth *AuthMaterial
	nilAuth.Apply(r) // must not panic
}

func TestRedactorLiterals(t *testing.T) {
	base := NewRedactor()
	token := "t0k3n-with-no-pattern-shape-zzz"
	run := base.WithLiterals(token, "")
	if got := run.Redact("Authorization: Bearer " + token + " here"); strings.Contains(got, token) {
		t.Fatalf("literal survived: %q", got)
	}
	if got := base.Redact(token); got != token {
		t.Fatalf("base redactor mutated: %q", got)
	}
	// Header-line patterns mask whole auth lines.
	for _, tc := range []struct{ line, secret string }{
		{"Cookie: session=abc", "abc"},
		{"Set-Cookie: s=1; Path=/", "s=1"},
		{"X-Api-Key: hunter2", "hunter2"},
		{"X-Auth-Token: hunter2", "hunter2"},
	} {
		if got := base.Redact("hdr\n" + tc.line + "\ntail"); strings.Contains(got, tc.secret) {
			t.Fatalf("line survived: %q", got)
		}
	}
	if got := base.Redact("Set-Cookie: s=1"); !strings.Contains(got, "Set-Cookie:") {
		t.Fatalf("key should stay visible: %q", got)
	}
}
