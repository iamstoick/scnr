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

func TestLoadAuthFileMySQL(t *testing.T) {
	a, err := LoadAuthFile(writeAuthFile(t, 0o600, "mysql:\n  user: auditor\n  password: s3cret\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasDBCredentials() || a.DBUser() != "auditor" {
		t.Fatalf("db login: %+v", a)
	}
	// Empty passwords are explicit and allowed; absence of the section is not a login.
	b, err := LoadAuthFile(writeAuthFile(t, 0o600, "mysql:\n  user: root\n  password: \"\"\n"))
	if err != nil || !b.HasDBCredentials() {
		t.Fatalf("empty password: %v %+v", err, b)
	}
	c, err := LoadAuthFile(writeAuthFile(t, 0o600, goodAuthYAML))
	if err != nil || c.HasDBCredentials() {
		t.Fatalf("headers-only file has db login: %v", err)
	}
	// The mysql login composes with headers/cookies in one file.
	d, err := LoadAuthFile(writeAuthFile(t, 0o600, goodAuthYAML+"mysql:\n  user: u\n  password: p\n"))
	if err != nil || d.HeaderCount() != 1 || !d.HasDBCredentials() {
		t.Fatalf("combined: %v %+v", err, d)
	}
}

func TestLoadAuthFileMySQLRefusals(t *testing.T) {
	for name, body := range map[string]string{
		"empty user":    "mysql:\n  user: \"\"\n  password: x\n",
		"missing user":  "mysql:\n  password: x\n",
		"user newline":  "mysql:\n  user: \"a\\nb\"\n  password: x\n",
		"pass newline":  "mysql:\n  user: u\n  password: \"a\\nb\"\n",
		"user NUL":      "mysql:\n  user: \"a\\x00b\"\n  password: x\n",
		"unknown field": "mysql:\n  user: u\n  password: x\n  db: foo\n",
	} {
		if _, err := LoadAuthFile(writeAuthFile(t, 0o600, body)); err == nil {
			t.Fatalf("%s accepted", name)
		} else if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "a\nb") {
			t.Fatalf("%s leaked value: %v", name, err)
		}
	}
	// A mysql-only section satisfies the non-empty rule.
	if _, err := LoadAuthFile(writeAuthFile(t, 0o600, "mysql:\n  user: u\n  password: p\n")); err != nil {
		t.Fatalf("mysql-only refused: %v", err)
	}
}

func TestDBCredentialsOriginOnly(t *testing.T) {
	a, err := LoadAuthFile(writeAuthFile(t, 0o600, "mysql:\n  user: auditor\n  password: s3cret\n"))
	if err != nil {
		t.Fatal(err)
	}
	bound := a.WithOrigin("192.168.0.136:3306")
	if a.Origin != "" {
		t.Fatal("WithOrigin mutated the receiver")
	}
	user, pass, ok := bound.DBCredentials("192.168.0.136:3306")
	if !ok || user != "auditor" || pass != "s3cret" {
		t.Fatalf("exact origin: %q %v", user, ok)
	}
	for _, origin := range []string{"192.168.0.137:3306", "192.168.0.136:3307", ""} {
		if _, _, ok := bound.DBCredentials(origin); ok {
			t.Fatalf("released for %q", origin)
		}
	}
	if _, _, ok := a.DBCredentials("192.168.0.136:3306"); ok {
		t.Fatal("unbound material released")
	}
	var nilAuth *AuthMaterial
	if nilAuth.HasDBCredentials() || nilAuth.DBUser() != "" {
		t.Fatal("nil material reports credentials")
	}
	if _, _, ok := nilAuth.DBCredentials("h:1"); ok {
		t.Fatal("nil material released")
	}
	// Merge carries the file login; flags cannot add one.
	merged := MergeAuth(a, MustParseForTest(t))
	if !merged.HasDBCredentials() || merged.DBUser() != "auditor" {
		t.Fatal("merge dropped db login")
	}
	if Merged := MergeAuth(nil, MustParseForTest(t)); Merged.HasDBCredentials() {
		t.Fatal("flags-only merge gained db login")
	}
}

func TestDBPasswordRedaction(t *testing.T) {
	a, err := LoadAuthFile(writeAuthFile(t, 0o600, "mysql:\n  user: auditor\n  password: s3cret-db-pw\n"))
	if err != nil {
		t.Fatal(err)
	}
	foundPass, foundUser := false, false
	for _, v := range a.Values() {
		foundPass = foundPass || v == "s3cret-db-pw"
		foundUser = foundUser || v == "auditor"
	}
	if !foundPass || foundUser {
		t.Fatalf("Values must carry the password, never the user: %q", a.Values())
	}
	other, err := LoadAuthFile(writeAuthFile(t, 0o600, "mysql:\n  user: auditor\n  password: different-pw\n"))
	if err != nil {
		t.Fatal(err)
	}
	if other.ValuesHash() == a.ValuesHash() {
		t.Fatal("hash ignores db password")
	}
}

func TestLoadAuthFileLogin(t *testing.T) {
	body := "login:\n  url: http://127.0.0.1:8080/login\n  user: auditor\n  password: s3cret\n  success: Dashboard\n"
	a, err := LoadAuthFile(writeAuthFile(t, 0o600, body))
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasLogin() || a.LoginUser() != "auditor" {
		t.Fatalf("login spec: %+v", a)
	}
	if _, ok := a.LoginFor("127.0.0.1:8080"); ok {
		t.Fatal("unbound material must not release")
	}
	bound := a.WithOrigin("127.0.0.1:8080")
	spec, ok := bound.LoginFor("127.0.0.1:8080")
	if !ok || spec.User != "auditor" || spec.Pass != "s3cret" || spec.UserField != "username" || spec.PassField != "password" {
		t.Fatalf("exact origin: %+v %v", spec, ok)
	}
	if _, ok := bound.LoginFor("127.0.0.1:9999"); ok {
		t.Fatal("released for another port")
	}
	// Password reaches the redactor literals and the values hash, never errors.
	found := false
	for _, v := range bound.Values() {
		if v == "s3cret" {
			found = true
		}
	}
	if !found {
		t.Fatal("login password missing from redactor literals")
	}
	if h1, h2 := a.ValuesHash(), bound.ValuesHash(); h1 == "" || h1 != h2 {
		t.Fatalf("values hash unstable: %q %q", h1, h2)
	}
	merged := MergeAuth(a, nil)
	if _, ok := merged.WithOrigin("127.0.0.1:8080").LoginFor("127.0.0.1:8080"); !ok {
		t.Fatal("merge dropped the login spec")
	}
}

func TestLoadAuthFileLoginRefusals(t *testing.T) {
	for name, body := range map[string]string{
		"missing password": "login:\n  url: http://h/login\n  user: u\n  success: ok\n",
		"missing success":  "login:\n  url: http://h/login\n  user: u\n  password: p\n",
		"bad scheme":       "login:\n  url: ftp://h/login\n  user: u\n  password: p\n  success: ok\n",
		"creds in url":     "login:\n  url: http://u:p@h/login\n  user: u\n  password: p\n  success: ok\n",
		"pass newline":     "login:\n  url: http://h/login\n  user: u\n  password: \"a\\nb\"\n  success: ok\n",
		"unknown field":    "login:\n  url: http://h/login\n  user: u\n  password: p\n  success: ok\n  extra2: x\n",
	} {
		if _, err := LoadAuthFile(writeAuthFile(t, 0o600, body)); err == nil {
			t.Fatalf("%s accepted", name)
		} else if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "a\nb") {
			t.Fatalf("%s leaked value: %v", name, err)
		}
	}
}
