package webscan

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
)

const goodTemplate = `id: my-check
info:
  title: T
  severity: low
  what: w
  why: y
  fix: f
safety: safe
http:
  - method: GET
    path: ["/x"]
    matchers:
      - type: status
        status: [200]
`

func TestEmbeddedTemplatesLoadAndAreSafe(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if e.EmbeddedCount() < 100 {
		t.Fatalf("expected ~100 embedded templates, got %d", e.EmbeddedCount())
	}
	tpls, err := e.Templates("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tp := range tpls {
		if tp.Safety != domain.SafetySafe {
			t.Fatalf("%s: embedded template is not safe", tp.ID)
		}
		for _, s := range tp.HTTP {
			if s.Method != http.MethodGet && s.Method != http.MethodHead {
				t.Fatalf("%s: method %s", tp.ID, s.Method)
			}
		}
	}
}

// Acceptance 2.1: the loader rejects >1 MiB, unknown fields, non-RE2 regex,
// bad IDs and safety values other than the two allowed.
func TestTemplateLoaderRejections(t *testing.T) {
	cases := map[string]struct {
		in   string
		want string
	}{
		"too big":        {goodTemplate + "# " + strings.Repeat("x", MaxTemplateBytes), "exceeds"},
		"unknown field":  {strings.Replace(goodTemplate, "safety: safe", "safety: safe\nnetwork: [{host: x}]", 1), "field network not found"},
		"unknown matcher field": {strings.Replace(goodTemplate, "status: [200]", "status: [200]\n        dsl: [\"1==1\"]", 1), "not found"},
		"backreference":  {strings.Replace(goodTemplate, "- type: status\n        status: [200]", "- type: regex\n        regex: ['(a)\\1']", 1), "not RE2"},
		"lookahead":      {strings.Replace(goodTemplate, "- type: status\n        status: [200]", "- type: regex\n        regex: ['(?=a)b']", 1), "not RE2"},
		"regex too long": {strings.Replace(goodTemplate, "- type: status\n        status: [200]", "- type: regex\n        regex: ['"+strings.Repeat("a", MaxRegexLen+1)+"']", 1), "length"},
		"regex too complex": {strings.Replace(goodTemplate, "- type: status\n        status: [200]", "- type: regex\n        regex: ['"+strings.Repeat("a{1,100}", 20)+"']", 1), "too complex"},
		"bad id upper":   {strings.Replace(goodTemplate, "id: my-check", "id: My-Check", 1), "bad template id"},
		"bad id short":   {strings.Replace(goodTemplate, "id: my-check", "id: ab", 1), "bad template id"},
		"bad id chars":   {strings.Replace(goodTemplate, "id: my-check", "id: my_check!", 1), "bad template id"},
		"safety third":   {strings.Replace(goodTemplate, "safety: safe", "safety: aggressive", 1), "safety must be"},
		"safety missing": {strings.Replace(goodTemplate, "safety: safe\n", "", 1), "safety must be"},
		"post on safe":   {strings.Replace(goodTemplate, "method: GET", "method: POST", 1), "POST is only permitted in intrusive"},
		"bad method":     {strings.Replace(goodTemplate, "method: GET", "method: DELETE", 1), "not permitted"},
		"path query":     {strings.Replace(goodTemplate, `path: ["/x"]`, `path: ["/x?a=1"]`, 1), "path"},
		"path traversal": {strings.Replace(goodTemplate, `path: ["/x"]`, `path: ["/a/../b"]`, 1), "path"},
		"path absolute url": {strings.Replace(goodTemplate, `path: ["/x"]`, `path: ["http://evil/"]`, 1), "path"},
		"path userinfo":  {strings.Replace(goodTemplate, `path: ["/x"]`, `path: ["/@evil.example/"]`, 1), "path"},
		"unsafe tag":     {strings.Replace(goodTemplate, "  fix: f", "  fix: f\n  tags: [dos]", 1), "not permitted"},
		"fuzz tag":       {strings.Replace(goodTemplate, "  fix: f", "  fix: f\n  tags: [fuzz]", 1), "not permitted"},
		"host header":    {strings.Replace(goodTemplate, `path: ["/x"]`, `path: ["/x"]`+"\n    headers: {Host: evil}", 1), "header"},
		"no matchers":    {strings.Replace(goodTemplate, "    matchers:\n      - type: status\n        status: [200]\n", "    matchers: []\n", 1), "matchers"},
		"bad severity":   {strings.Replace(goodTemplate, "severity: low", "severity: urgent", 1), "bad severity"},
		"two docs":       {goodTemplate + "---\n" + goodTemplate, "one template per file"},
		"missing prose":  {strings.Replace(goodTemplate, "  fix: f\n", "", 1), "required"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTemplate([]byte(c.in), "t.yaml")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
	if _, err := ParseTemplate([]byte(goodTemplate), "ok.yaml"); err != nil {
		t.Fatalf("good template rejected: %v", err)
	}
}

func TestIntrusiveTemplatesParseButDoNotRun(t *testing.T) {
	intrusive := strings.Replace(strings.Replace(goodTemplate, "safety: safe", "safety: intrusive", 1), "id: my-check", "id: my-post", 1)
	intrusive = strings.Replace(intrusive, "method: GET", "method: POST\n    body: a=b", 1)
	tp, err := ParseTemplate([]byte(intrusive), "i.yaml")
	if err != nil || tp.Safety != domain.SafetyIntrusive {
		t.Fatalf("%v %+v", err, tp)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "i.yaml"), []byte(intrusive), 0o600)
	os.WriteFile(filepath.Join(dir, "g.yaml"), []byte(goodTemplate), 0o600)
	e, _ := New()
	tpls, err := e.Templates(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tp := range tpls {
		if tp.ID == "my-post" {
			t.Fatal("intrusive template must not be scheduled")
		}
	}
	found := false
	for _, tp := range tpls {
		if tp.ID == "my-check" {
			found = true
		}
	}
	if !found {
		t.Fatal("user template not merged")
	}
	// A broken user template fails the whole directory (never silently skipped).
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(strings.Replace(goodTemplate, "safety: safe", "safety: x", 1)), 0o600)
	if _, err := e.Templates(dir); err == nil || !strings.Contains(err.Error(), "safety must be") {
		t.Fatalf("bad user template accepted: %v", err)
	}
}

func TestMatchers(t *testing.T) {
	r := &Response{Status: 200, Header: http.Header{"Server": {"nginx/1.2"}, "Set-Cookie": {"a=b"}}, Body: []byte("Hello World INDEX")}
	for _, c := range []struct {
		m    Matcher
		want bool
	}{
		{Matcher{Type: "status", Status: []int{200}}, true},
		{Matcher{Type: "status", Status: []int{404}}, false},
		{Matcher{Type: "status", Status: []int{404}, Negative: true}, true},
		{Matcher{Type: "word", Words: []string{"World"}}, true},
		{Matcher{Type: "word", Words: []string{"world"}}, false},
		{Matcher{Type: "word", Words: []string{"world"}, CaseInsensitive: true}, true},
		{Matcher{Type: "word", Words: []string{"Hello", "nope"}}, true},
		{Matcher{Type: "word", Words: []string{"Hello", "nope"}, Condition: "and"}, false},
		{Matcher{Type: "word", Words: []string{"nginx"}, Part: "header"}, true},
		{Matcher{Type: "word", Words: []string{"nginx"}}, false},
		{Matcher{Type: "regex", Regex: []string{`(?i)hello\s+world`}}, true},
		{Matcher{Type: "header", Name: "Server", Words: []string{"nginx"}}, true},
		{Matcher{Type: "header", Name: "Server", Regex: []string{`^nginx/\d`}}, true},
		{Matcher{Type: "header", Name: "X-Nope", Words: []string{"x"}}, false},
		{Matcher{Type: "size", Size: []int{17}}, true},
	} {
		m := c.m
		if err := m.compile(); err != nil {
			t.Fatal(err)
		}
		if got := m.Match(r); got != c.want {
			t.Errorf("%+v: got %v", c.m, got)
		}
	}
	st := Step{MatchersCondition: "or", Matchers: []Matcher{{Type: "status", Status: []int{500}}, {Type: "word", Words: []string{"Hello"}}}}
	for i := range st.Matchers {
		st.Matchers[i].compile()
	}
	if !st.Matches(r) {
		t.Fatal("or condition")
	}
	st.MatchersCondition = "and"
	if st.Matches(r) {
		t.Fatal("and condition")
	}
	x := Extractor{Type: "regex", Regex: []string{`Hello (\w+)`}, Group: 1}
	x.compile()
	if got := x.Extract(r); len(got) != 1 || got[0] != "World" {
		t.Fatalf("extract %v", got)
	}
}

type staticResolver map[string][]string

func (s staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := s[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, ip := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
	}
	return out, nil
}

func newOpts(t *testing.T, allow []string, public bool, res safety.Resolver) (engine.Options, *safety.Dialer) {
	t.Helper()
	scope, err := safety.NewScope(allow, nil)
	if err != nil {
		t.Fatal(err)
	}
	limits, _, _ := safety.NewLimits(public, safety.LimitRequest{HTTPRPSPerHost: 20})
	d := &safety.Dialer{Scope: scope, Resolver: res, Limits: limits}
	client := safety.NewHTTPClient(d, safety.HTTPOptions{Timeout: 5 * time.Second})
	p, _ := engine.ProfileByName("standard")
	return engine.Options{Profile: p, Limiter: limits, HTTP: client, Scope: scope, Dialer: d, Redactor: safety.NewRedactor(), Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}, d
}

func collect(t *testing.T, e *Engine, target domain.Target, o engine.Options) (map[string][]domain.Finding, error) {
	t.Helper()
	out := map[string][]domain.Finding{}
	err := e.Run(context.Background(), target, o, func(f domain.Finding) error {
		out[f.RuleID] = append(out[f.RuleID], f)
		return nil
	})
	return out, err
}

func TestPassiveAndTemplatesAgainstLocalServer(t *testing.T) {
	const secret = "DB_PASSWORD=SuperSecretValue123"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Add("Set-Cookie", "session=abc123; Path=/")
		w.Header().Add("Set-Cookie", "ok=1; Secure; HttpOnly; SameSite=Lax")
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Write([]byte("<html><title>Index of /</title><a href=../>Parent Directory</a></html>"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(secret + "\nAPP_ENV=prod\n")) })
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ref: refs/heads/main\n")) })
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("User-agent: *\nDisallow: /admin\n")) })
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o, _ := newOpts(t, nil, false, nil)
	target := domain.Target{Raw: srv.URL, Type: domain.TargetURL, Value: srv.URL + "/", Hostname: "127.0.0.1"}
	got, err := collect(t, e, target, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"web.header.csp-missing", "web.header.xcto-missing", "web.header.frame-protection-missing", "web.cookie.insecure-flags",
		"web.server-version-disclosure", "web.cors.credentials-any-origin", "web.tpl.exposed-env-file", "web.tpl.exposed-git-head", "web.tpl.directory-listing",
		"web.tpl.robots-txt", "web.tpl.security-txt-missing"} {
		if len(got[want]) == 0 {
			t.Errorf("missing %s (have %v)", want, keys(got))
		}
	}
	if len(got["web.header.hsts-missing"]) != 0 {
		t.Error("HSTS must not be required on plain http")
	}
	if len(got["web.cookie.insecure-flags"]) != 1 || !strings.Contains(got["web.cookie.insecure-flags"][0].Title, `"session"`) {
		t.Errorf("cookie findings: %+v", got["web.cookie.insecure-flags"])
	}
	// Hostile/secret content: the .env body is never quoted for a critical
	// template, and nothing anywhere contains the raw secret value.
	for id, fs := range got {
		for _, f := range fs {
			for _, ev := range f.Evidence {
				if strings.Contains(ev.Redacted, "SuperSecretValue123") {
					t.Errorf("%s evidence leaks secret: %q", id, ev.Redacted)
				}
			}
			if f.Fingerprint == "" || f.AssetKey != target.AssetKey() || f.Title == "" || f.HowToFix == "" {
				t.Errorf("%s: incomplete finding %+v", id, f)
			}
		}
	}
	env := got["web.tpl.exposed-env-file"][0]
	if env.Severity != domain.Critical || !strings.HasSuffix(env.Location, "/.env") || len(env.Evidence) != 1 || strings.Contains(env.Evidence[0].Redacted, "APP_ENV") {
		t.Errorf("env finding %+v", env)
	}
	// Plan sizes the work from the template count.
	p, err := e.Plan(context.Background(), target, o)
	if err != nil || p.EstRequests < 100 || !p.Network {
		t.Fatalf("plan %+v %v", p, err)
	}
}

// Security rule: a scan authorised for a public target must never follow a
// redirect into loopback/private space; it becomes web.redirect-out-of-scope.
func TestRedirectIntoPrivateFromPublicTargetNotFollowed(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("internal server was reached: %s", r.URL)
	}))
	defer internal.Close()
	// "public.test" is served by a loopback listener but resolves (in our fake
	// resolver) to a public address pinned at authorisation time; the dialer
	// connects to the resolved IP, so we point the fake at the real listener
	// and mark the target public via a second name.
	pub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			http.Redirect(w, r, internal.URL+"/.env", http.StatusFound)
			return
		}
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer pub.Close()
	_, port, _ := net.SplitHostPort(pub.Listener.Addr().String())
	res := staticResolver{"public.test": {"127.0.0.1"}}
	o, d := newOpts(t, []string{"public.test"}, false, res)
	// Simulate the gate having pinned a public address for the target so
	// the dialer applies public-scan rules to everything else.
	d.Pin("public.test", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.10")})
	e, _ := New()
	target := domain.Target{Raw: "http://public.test:" + port + "/", Type: domain.TargetURL, Value: "http://public.test:" + port + "/", Hostname: "public.test", Public: true}
	got, err := collect(t, e, target, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["web.redirect-out-of-scope"]) == 0 {
		t.Fatalf("expected redirect-out-of-scope, got %v", keys(got))
	}
	for _, f := range got["web.redirect-out-of-scope"] {
		if !strings.Contains(f.Evidence[0].Redacted, "not followed") {
			t.Errorf("evidence %+v", f.Evidence)
		}
	}
	if len(got["web.tpl.exposed-env-file"]) != 0 {
		t.Fatal("redirected .env must not match")
	}
}

// recordRT records every request URL and answers 404 without a network.
type recordRT struct {
	mu   sync.Mutex
	urls []string
}

func (r *recordRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.urls = append(r.urls, req.URL.String())
	r.mu.Unlock()
	return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// Finding 2: with a URL-prefix allow entry (https://app.example/app), the
// template engine never requests a path outside that prefix; out-of-prefix
// paths are skipped, and the in-prefix passive request still goes out.
func TestTemplatesNeverLeaveAllowedURLPrefix(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := safety.NewScope([]string{"https://app.example/app"}, nil)
	ips := []netip.Addr{netip.MustParseAddr("203.0.113.5")}
	d := &safety.Dialer{Scope: scope}
	d.Pin("app.example", ips)
	rt := &recordRT{}
	o := engine.Options{HTTP: &http.Client{Transport: rt}, Scope: scope, Dialer: d, Redactor: safety.NewRedactor()}
	tg := domain.Target{Type: domain.TargetURL, Value: "https://app.example/app/", Hostname: "app.example", Public: true}
	if err := e.Run(context.Background(), tg, o, func(domain.Finding) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(rt.urls) == 0 {
		t.Fatal("no requests sent at all")
	}
	for _, u := range rt.urls {
		if _, err := scope.Check("app.example", ips, u); err != nil {
			t.Errorf("request outside the allowed prefix was sent: %s", u)
		}
	}
	tpls, _ := e.Templates("")
	if len(rt.urls) >= 1+countRequests(tpls) {
		t.Fatalf("expected out-of-prefix template paths to be skipped, but %d of %d requests were sent", len(rt.urls), 1+countRequests(tpls))
	}
	// Without a path prefix every template path is in scope and all are sent.
	full, _ := safety.NewScope([]string{"https://app.example"}, nil)
	d2 := &safety.Dialer{Scope: full}
	d2.Pin("app.example", ips)
	rt2 := &recordRT{}
	o2 := engine.Options{HTTP: &http.Client{Transport: rt2}, Scope: full, Dialer: d2, Redactor: safety.NewRedactor()}
	if err := e.Run(context.Background(), tg, o2, func(domain.Finding) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(rt2.urls) != 1+countRequests(tpls) {
		t.Fatalf("host-wide allow: %d of %d requests sent", len(rt2.urls), 1+countRequests(tpls))
	}
}

func TestRunRequiresSafeClient(t *testing.T) {
	e, _ := New()
	err := e.Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "http://127.0.0.1/"}, engine.Options{}, func(domain.Finding) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "scope-checked") {
		t.Fatalf("err %v", err)
	}
	o, _ := newOpts(t, nil, false, nil)
	if err := e.Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "http://u:p@127.0.0.1/"}, o, nil); err == nil {
		t.Fatal("userinfo in target accepted")
	}
}

func keys(m map[string][]domain.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
