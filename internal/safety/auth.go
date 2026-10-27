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

// AuthMaterial carries authenticated-scan credentials (headers, cookies,
// database login) for exactly one origin. Values are unexported, never
// formatted and never serialised; Apply copies them onto a request only
// when the request's host:port equals Origin, and DBCredentials releases
// the database login only for that same origin.
type AuthMaterial struct {
	// Origin is the "host:port" authorised to receive the material, taken
	// from the target URL (web) or the probed host:port (database).
	// Empty matches nothing.
	Origin  string
	headers http.Header
	cookies []*http.Cookie
	dbUser  string
	dbPass  string
	hasDB   bool
	login   *LoginSpec
}

// LoginSpec is one form-login attempt: POST url-encoded fields to URL and
// keep the session cookies on success. The URL must share the scan
// target's origin; the attempt runs once, never retried, never guessed.
type LoginSpec struct {
	URL          string
	UserField    string
	User         string
	PassField    string
	Pass         string
	Extra        map[string]string
	Success      string
	Origin       string
}

// MaxAuthFileBytes caps --auth-file at 64 KiB.
const MaxAuthFileBytes = 64 << 10

type authFile struct {
	Headers map[string]string `yaml:"headers"`
	Cookies map[string]string `yaml:"cookies"`
	Mysql   *mysqlAuthFile    `yaml:"mysql"`
	Login   *loginAuthFile    `yaml:"login"`
}

// loginAuthFile is the optional form login: {login: {url, user_field,
// user, password_field, password, extra: {k: v}, success: marker}}.
// Field names default to username/password; success is a required
// substring (or /re/ regex) in the post-login response.
type loginAuthFile struct {
	URL           string            `yaml:"url"`
	UserField     string            `yaml:"user_field"`
	User          string            `yaml:"user"`
	PasswordField string            `yaml:"password_field"`
	Password      string            `yaml:"password"`
	Extra         map[string]string `yaml:"extra"`
	Success       string            `yaml:"success"`
}

// mysqlAuthFile is the optional database login: {mysql: {user: name,
// password: secret}}. The password may be empty (an explicitly
// passwordless login); absence of the section means no database login.
type mysqlAuthFile struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

// LoadAuthFile reads an --auth-file: strict YAML
// ({headers: {Name: value}, cookies: {name: value}, mysql: {user,
// password}, login: {url, user, password, ...}}), at most 64 KiB, mode
// 0600, owned by the current uid, never a symlink. Errors name the path
// and the reason only: values never appear in them.
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
	if af.Mysql != nil {
		user := strings.TrimSpace(af.Mysql.User)
		if user == "" {
			return nil, fmt.Errorf("auth file %s: mysql user is empty", path)
		}
		// NUL would truncate the wire encoding and log the password
		// beside it; line breaks would corrupt error text. Reject both.
		if strings.ContainsAny(user, "\r\n\x00") || strings.ContainsAny(af.Mysql.Password, "\r\n\x00") {
			return nil, fmt.Errorf("auth file %s: mysql credentials contain a line break or NUL", path)
		}
		a.dbUser, a.dbPass, a.hasDB = user, af.Mysql.Password, true
	}
	if af.Login != nil {
		l := af.Login
		u, err := url.Parse(strings.TrimSpace(l.URL))
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return nil, fmt.Errorf("auth file %s: login url must be an http(s) URL without credentials", path)
		}
		userField, passField := strings.TrimSpace(l.UserField), strings.TrimSpace(l.PasswordField)
		if userField == "" {
			userField = "username"
		}
		if passField == "" {
			passField = "password"
		}
		user := strings.TrimSpace(l.User)
		if user == "" || l.Password == "" || strings.TrimSpace(l.Success) == "" {
			return nil, fmt.Errorf("auth file %s: login needs user, password and success", path)
		}
		check := []string{userField, passField, user, l.Password, l.Success}
		for _, v := range l.Extra {
			check = append(check, v)
		}
		for _, v := range check {
			if strings.ContainsAny(v, "\r\n\x00") {
				return nil, fmt.Errorf("auth file %s: login values must not contain line breaks or NUL", path)
			}
		}
		extra := map[string]string{}
		for k, v := range l.Extra {
			k = strings.TrimSpace(k)
			if k == "" {
				return nil, fmt.Errorf("auth file %s: login extra has an empty field name", path)
			}
			extra[k] = v
		}
		a.login = &LoginSpec{URL: u.String(), UserField: userField, User: user, PassField: passField,
			Pass: l.Password, Extra: extra, Success: strings.TrimSpace(l.Success), Origin: OriginHostPort(u)}
	}
	if len(a.headers) == 0 && len(a.cookies) == 0 && !a.hasDB && a.login == nil {
		return nil, fmt.Errorf("auth file %s: no headers, cookies, mysql or login credentials", path)
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
// nil; the result shares no mutable state with the inputs. Only the file
// can carry a database login (there are no --db-user/--db-password flags:
// passwords must never appear on a command line).
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
		if src.hasDB && !out.hasDB {
			out.dbUser, out.dbPass, out.hasDB = src.dbUser, src.dbPass, true
		}
		if src.login != nil && out.login == nil {
			cp := *src.login
			cp.Extra = mapsClone(src.login.Extra)
			out.login = &cp
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
	out.dbUser, out.dbPass, out.hasDB = a.dbUser, a.dbPass, a.hasDB
	if a.login != nil {
		cp := *a.login
		cp.Extra = mapsClone(a.login.Extra)
		out.login = &cp
	}
	return out
}

// mapsClone copies a small string map (nil stays nil).
func mapsClone(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
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

// HasDBCredentials reports whether a database login is present (origin
// not yet checked).
func (a *AuthMaterial) HasDBCredentials() bool { return a != nil && a.hasDB }

// HasLogin reports whether a form-login spec is present (origin and
// target match not yet checked).
func (a *AuthMaterial) HasLogin() bool { return a != nil && a.login != nil }

// LoginUser returns the login username for plan lines. Usernames are
// not secrets; the password is never exposed except via LoginFor.
func (a *AuthMaterial) LoginUser() string {
	if a == nil || a.login == nil {
		return ""
	}
	return a.login.User
}

// LoginFor releases the login spec only when origin equals the
// authorised Origin — the same origin check as Apply and DBCredentials.
// Anything else, including an empty Origin, gets nothing.
func (a *AuthMaterial) LoginFor(origin string) (*LoginSpec, bool) {
	if a == nil || a.login == nil || a.Origin == "" || origin != a.Origin {
		return nil, false
	}
	cp := *a.login
	cp.Extra = mapsClone(a.login.Extra)
	return &cp, true
}

// DBUser returns the database login name for plan lines. Usernames are
// not secrets; the password is never exposed except via DBCredentials.
func (a *AuthMaterial) DBUser() string {
	if a == nil || !a.hasDB {
		return ""
	}
	return a.dbUser
}

// DBCredentials releases the database login only when origin equals the
// authorised Origin — the database equivalent of Apply's origin check.
// Anything else, including an empty Origin, gets nothing.
func (a *AuthMaterial) DBCredentials(origin string) (user, pass string, ok bool) {
	if a == nil || !a.hasDB || a.Origin == "" || origin != a.Origin {
		return "", "", false
	}
	return a.dbUser, a.dbPass, true
}

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
// use is seeding the run redactor's literal list. The database username
// is not a secret (findings name accounts) and is deliberately excluded.
func (a *AuthMaterial) Values() []string {
	var out []string
	for _, vs := range a.headers {
		out = append(out, vs...)
	}
	for _, c := range a.cookies {
		out = append(out, c.Value)
	}
	if a.hasDB && a.dbPass != "" {
		out = append(out, a.dbPass)
	}
	if a.login != nil {
		out = append(out, a.login.Pass)
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
	if a.hasDB {
		pairs = append(pairs, "mysql:"+a.dbUser+"="+a.dbPass)
	}
	if a.login != nil {
		pairs = append(pairs, "login:"+a.login.URL+"="+a.login.User+"="+a.login.Pass)
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
