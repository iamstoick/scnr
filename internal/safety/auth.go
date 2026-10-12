package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthMaterial carries authenticated-scan credentials (headers, cookies)
// for exactly one origin. Values are unexported, never formatted and
// never serialised; Apply copies them onto a request only when the
// request's host:port equals Origin.
type AuthMaterial struct {
	// Origin is the "host:port" authorised to receive the material, taken
	// from the target URL. Empty matches nothing.
	Origin  string
	headers http.Header
	cookies []*http.Cookie
}

// MaxAuthFileBytes caps --auth-file at 64 KiB.
const MaxAuthFileBytes = 64 << 10

type authFile struct {
	Headers map[string]string `yaml:"headers"`
	Cookies map[string]string `yaml:"cookies"`
}

// LoadAuthFile reads an --auth-file: strict YAML
// ({headers: {Name: value}, cookies: {name: value}}), at most 64 KiB,
// mode 0600, owned by the current uid, never a symlink. Errors name the
// path and the reason only: values never appear in them.
func LoadAuthFile(path string) (*AuthMaterial, error) {
	if err := CheckPrivateFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("auth file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxAuthFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("auth file %s: %w", path, err)
	}
	if len(b) > MaxAuthFileBytes {
		return nil, fmt.Errorf("auth file %s: exceeds %d bytes", path, MaxAuthFileBytes)
	}
	var af authFile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&af); err != nil {
		return nil, fmt.Errorf("auth file %s: %w", path, err)
	}
	a := &AuthMaterial{headers: http.Header{}, cookies: nil}
	for k, v := range af.Headers {
		k = strings.TrimSpace(k)
		if k == "" || v == "" {
			return nil, fmt.Errorf("auth file %s: empty header name or value", path)
		}
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("auth file %s: header %q contains a line break", path, k)
		}
		a.headers.Add(k, v)
	}
	for k, v := range af.Cookies {
		k = strings.TrimSpace(k)
		if k == "" || v == "" {
			return nil, fmt.Errorf("auth file %s: empty cookie name or value", path)
		}
		if strings.ContainsAny(k, "\r\n;") || strings.ContainsAny(v, "\r\n;") {
			return nil, fmt.Errorf("auth file %s: cookie %q contains a separator", path, k)
		}
		a.cookies = append(a.cookies, &http.Cookie{Name: k, Value: v})
	}
	if len(a.headers) == 0 && len(a.cookies) == 0 {
		return nil, fmt.Errorf("auth file %s: no headers or cookies", path)
	}
	return a, nil
}

// ParseAuthLiterals builds material from --header "Name: value" and
// --cookie "name=value" flags (interactive use only; schedules refuse
// them). Same value hygiene as LoadAuthFile; errors never echo values.
func ParseAuthLiterals(headers, cookies []string) (*AuthMaterial, error) {
	a := &AuthMaterial{headers: http.Header{}}
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, errors.New(`--header must be "Name: value"`)
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("--header %q contains a line break", name)
		}
		a.headers.Add(name, value)
	}
	for _, c := range cookies {
		name, value, ok := strings.Cut(c, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, errors.New(`--cookie must be "name=value"`)
		}
		if strings.ContainsAny(name, "\r\n;") || strings.ContainsAny(value, "\r\n;") {
			return nil, fmt.Errorf("--cookie %q contains a separator", name)
		}
		a.cookies = append(a.cookies, &http.Cookie{Name: name, Value: value})
	}
	if len(a.headers) == 0 && len(a.cookies) == 0 {
		return nil, errors.New("no auth material")
	}
	return a, nil
}

// MergeAuth combines file and flag material (file first). Either may be
// nil; the result shares no mutable state with the inputs.
func MergeAuth(file, flags *AuthMaterial) *AuthMaterial {
	out := &AuthMaterial{headers: http.Header{}}
	for _, src := range []*AuthMaterial{file, flags} {
		if src == nil {
			continue
		}
		for k, vs := range src.headers {
			for _, v := range vs {
				out.headers.Add(k, v)
			}
		}
		for _, c := range src.cookies {
			cp := *c
			out.cookies = append(out.cookies, &cp)
		}
	}
	return out
}

// WithOrigin returns a copy authorised for origin ("host:port").
func (a *AuthMaterial) WithOrigin(origin string) *AuthMaterial {
	out := &AuthMaterial{Origin: origin, headers: http.Header{}}
	for k, vs := range a.headers {
		out.headers[k] = append([]string(nil), vs...)
	}
	for _, c := range a.cookies {
		cp := *c
		out.cookies = append(out.cookies, &cp)
	}
	return out
}

// OriginHostPort normalises u to the "host:port" form Apply compares:
// lowercased host, explicit effective port (so http://h/ and
// http://h:80/ authorise each other).
func OriginHostPort(u *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if port == "" {
		port = "443"
		if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

// Apply copies the headers and cookies onto req when req targets Origin.
// Anything else — other hosts, redirects elsewhere, an empty Origin —
// gets nothing.
func (a *AuthMaterial) Apply(req *http.Request) {
	if a == nil || a.Origin == "" || req == nil || req.URL == nil {
		return
	}
	if OriginHostPort(req.URL) != a.Origin {
		return
	}
	for k, vs := range a.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, c := range a.cookies {
		req.AddCookie(c)
	}
}

// HeaderCount and CookieCount size the "authenticated: yes (…)" plan line.
func (a *AuthMaterial) HeaderCount() int { return len(a.headers) }
func (a *AuthMaterial) CookieCount() int { return len(a.cookies) }

// CookieNames lists the session cookie names (names only, never values)
// so the prober can notice when the server clears one.
func (a *AuthMaterial) CookieNames() []string {
	var out []string
	for _, c := range a.cookies {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

// Values returns every secret value. Handle with care: the only sanctioned
// use is seeding the run redactor's literal list.
func (a *AuthMaterial) Values() []string {
	var out []string
	for _, vs := range a.headers {
		out = append(out, vs...)
	}
	for _, c := range a.cookies {
		out = append(out, c.Value)
	}
	return out
}

// ValuesHash is sha256 over the sorted "name=value" pairs: the only form
// in which auth values reach the audit trail. Note it is a plain digest,
// not the install-keyed HMAC of SecretHash — session tokens are
// high-entropy bearer values, and the audit store is trusted to the same
// degree as the scan database.
func (a *AuthMaterial) ValuesHash() string {
	var pairs []string
	for k, vs := range a.headers {
		for _, v := range vs {
			pairs = append(pairs, strings.ToLower(k)+"="+v)
		}
	}
	for _, c := range a.cookies {
		pairs = append(pairs, "cookie:"+c.Name+"="+c.Value)
	}
	sort.Strings(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	return hex.EncodeToString(sum[:])
}

// String never formats the values.
func (a *AuthMaterial) String() string { return "<redacted auth material>" }

// MarshalJSON refuses: auth material must never be serialised by accident
// (audit detail, plan text, error wrapping with %+v is fine — String wins).
func (a *AuthMaterial) MarshalJSON() ([]byte, error) {
	return nil, errors.New("auth material is not serialisable")
}

// CheckPrivateFile requires path to be a regular non-symlink file with
// mode exactly 0600 owned by the current uid.
func CheckPrivateFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("auth file %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("auth file %s: must not be a symlink", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("auth file %s: not a regular file", path)
	}
	return checkFilePrivate(path, fi)
}
