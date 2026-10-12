package safety

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/store"
)

// fakeResolver maps hostnames to address lists; answers can be changed
// between calls to simulate DNS rebinding.
type fakeResolver struct {
	mu    sync.Mutex
	hosts map[string][]string
	txt   map[string][]string
	calls int
	// onCall, if set, mutates hosts after the nth call.
	onCall func(n int, r *fakeResolver)
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.onCall != nil {
		f.onCall(f.calls, f)
	}
	ips, ok := f.hosts[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.txt[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func mustScope(t *testing.T, allow, deny []string) *Scope {
	t.Helper()
	s, err := NewScope(allow, deny, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func refusalCode(err error) string {
	var r *RefusalError
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

func TestGateTable(t *testing.T) {
	res := &fakeResolver{hosts: map[string][]string{
		"intranet.test": {"10.1.2.3"},
		"public.test":   {"203.0.113.10"},
		"denied.test":   {"203.0.113.20"},
		"mixed.test":    {"10.0.0.1", "203.0.113.30"},
	}}
	verified := func(hosts ...string) VerifiedFunc {
		return func(_ context.Context, h string) (bool, error) {
			for _, x := range hosts {
				if x == h {
					return true, nil
				}
			}
			return false, nil
		}
	}
	consentYes := func(context.Context, domain.Target, string) (bool, error) { return true, nil }
	consentNo := func(context.Context, domain.Target, string) (bool, error) { return false, nil }

	cases := []struct {
		name     string
		target   domain.Target
		allow    []string
		deny     []string
		ack      bool
		verified VerifiedFunc
		consent  ConsentFunc
		maxHosts int
		wantCode string
		wantCons string
	}{
		{"no ack refused", domain.Target{Type: domain.TargetHost, Value: "10.1.2.3", Hostname: "10.1.2.3"}, nil, nil, false, nil, nil, 0, CodeAckRequired, ""},
		{"private host allowed", domain.Target{Type: domain.TargetHost, Value: "10.1.2.3", Hostname: "10.1.2.3"}, nil, nil, true, nil, nil, 0, "", domain.ConsentPrivateRange},
		{"private hostname allowed", domain.Target{Type: domain.TargetHost, Value: "intranet.test", Hostname: "intranet.test"}, nil, nil, true, nil, nil, 0, "", domain.ConsentPrivateRange},
		{"loopback allowed", domain.Target{Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}, nil, nil, true, nil, nil, 0, "", domain.ConsentPrivateRange},
		{"path ack only", domain.Target{Type: domain.TargetPath, Value: "/tmp/x"}, nil, nil, true, nil, nil, 0, "", domain.ConsentLocal},
		{"public not in allow refused", domain.Target{Type: domain.TargetHost, Value: "public.test", Hostname: "public.test"}, nil, nil, true, verified("public.test"), consentYes, 0, CodeScopeNotAllowed, ""},
		{"public non-interactive unverified refused", domain.Target{Type: domain.TargetHost, Value: "public.test", Hostname: "public.test"}, []string{"public.test"}, nil, true, nil, nil, 0, CodeOwnershipRequired, ""},
		{"public verified allowed", domain.Target{Type: domain.TargetHost, Value: "public.test", Hostname: "public.test"}, []string{"public.test"}, nil, true, verified("public.test"), nil, 0, "", domain.ConsentDNSTXT},
		{"public interactive consent allowed", domain.Target{Type: domain.TargetHost, Value: "public.test", Hostname: "public.test"}, []string{"*.test"}, nil, true, nil, consentYes, 0, "", domain.ConsentInteractive},
		{"public consent declined", domain.Target{Type: domain.TargetHost, Value: "public.test", Hostname: "public.test"}, []string{"public.test"}, nil, true, nil, consentNo, 0, CodeConsentDeclined, ""},
		{"public in deny refused even if verified", domain.Target{Type: domain.TargetHost, Value: "denied.test", Hostname: "denied.test"}, []string{"denied.test"}, []string{"denied.test"}, true, verified("denied.test"), consentYes, 0, CodeScopeDenied, ""},
		{"deny by resolved IP wins", domain.Target{Type: domain.TargetHost, Value: "denied.test", Hostname: "denied.test"}, []string{"denied.test"}, []string{"203.0.113.0/24"}, true, verified("denied.test"), consentYes, 0, CodeScopeDenied, ""},
		{"private deny wins", domain.Target{Type: domain.TargetHost, Value: "10.1.2.3", Hostname: "10.1.2.3"}, nil, []string{"10.1.2.3"}, true, nil, nil, 0, CodeScopeDenied, ""},
		{"mixed resolution counts as public", domain.Target{Type: domain.TargetHost, Value: "mixed.test", Hostname: "mixed.test"}, nil, nil, true, nil, nil, 0, CodeScopeNotAllowed, ""},
		{"bare public IP non-interactive refused", domain.Target{Type: domain.TargetHost, Value: "203.0.113.10", Hostname: "203.0.113.10"}, []string{"203.0.113.10"}, nil, true, nil, nil, 0, CodeOwnershipRequired, ""},
		{"url public verified", domain.Target{Type: domain.TargetURL, Value: "https://public.test/", Hostname: "public.test"}, []string{"https://public.test"}, nil, true, verified("public.test"), nil, 0, "", domain.ConsentDNSTXT},
		{"private /24 allowed", domain.Target{Type: domain.TargetCIDR, Value: "10.0.0.0/24"}, nil, nil, true, nil, nil, 0, "", domain.ConsentPrivateRange},
		{"private /16 allowed at cap", domain.Target{Type: domain.TargetCIDR, Value: "10.0.0.0/16"}, nil, nil, true, nil, nil, 0, "", domain.ConsentPrivateRange},
		{"private /15 refused without max-hosts", domain.Target{Type: domain.TargetCIDR, Value: "10.0.0.0/15"}, nil, nil, true, nil, nil, 0, CodeCIDRTooLarge, ""},
		{"private /15 allowed with max-hosts", domain.Target{Type: domain.TargetCIDR, Value: "10.0.0.0/15"}, nil, nil, true, nil, nil, 1 << 17, "", domain.ConsentPrivateRange},
		{"cidr fully denied", domain.Target{Type: domain.TargetCIDR, Value: "10.0.0.0/24"}, nil, []string{"10.0.0.0/16"}, true, nil, nil, 0, CodeScopeDenied, ""},
		{"public /24 non-interactive refused", domain.Target{Type: domain.TargetCIDR, Value: "203.0.113.0/24"}, []string{"203.0.113.0/24"}, nil, true, nil, nil, 0, CodeOwnershipRequired, ""},
		{"public /23 too large", domain.Target{Type: domain.TargetCIDR, Value: "203.0.112.0/23"}, []string{"203.0.112.0/23"}, nil, true, nil, consentYes, 0, CodeCIDRTooLarge, ""},
		{"public /24 interactive allowed", domain.Target{Type: domain.TargetCIDR, Value: "203.0.113.0/24"}, []string{"203.0.113.0/24"}, nil, true, nil, consentYes, 0, "", domain.ConsentInteractive},
		{"metadata endpoint built-in deny", domain.Target{Type: domain.TargetHost, Value: "169.254.169.254", Hostname: "169.254.169.254"}, nil, nil, true, nil, nil, 0, CodeScopeDenied, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := &Gate{Scope: mustScope(t, c.allow, c.deny), Acknowledged: c.ack, Resolver: res, Verified: c.verified, Consent: c.consent, MaxHosts: c.maxHosts}
			c.target.Raw = c.target.Value
			dec, err := g.Decide(context.Background(), c.target, "plan")
			if c.wantCode != "" {
				if err == nil {
					t.Fatalf("expected refusal %s, got allow %+v", c.wantCode, dec)
				}
				if got := refusalCode(err); got != c.wantCode {
					t.Fatalf("code = %s, want %s (%v)", got, c.wantCode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if dec.ConsentMethod != c.wantCons {
				t.Fatalf("consent = %s, want %s", dec.ConsentMethod, c.wantCons)
			}
		})
	}
}

func TestIsPrivate(t *testing.T) {
	priv := []string{"10.0.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fc00::1", "fd12::1", "0.0.0.0"}
	pub := []string{"8.8.8.8", "203.0.113.1", "2001:db8::1", "172.32.0.1", "100.128.0.1"}
	for _, p := range priv {
		if !IsPrivate(netip.MustParseAddr(p)) {
			t.Errorf("%s should be private", p)
		}
	}
	for _, p := range pub {
		if IsPrivate(netip.MustParseAddr(p)) {
			t.Errorf("%s should be public", p)
		}
	}
}

func TestScopeEntries(t *testing.T) {
	s := mustScope(t, []string{"10.0.0.0/8", "app.example.test", "*.wild.test", "https://staging.example.test", "203.0.113.5"}, []string{"*.prod.example.test"})
	ip := func(s string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(s)} }
	if !s.Allowed("", ip("10.9.9.9"), "") {
		t.Error("cidr allow")
	}
	if !s.Allowed("APP.example.test", ip("203.0.113.9"), "") {
		t.Error("hostname allow case-insensitive")
	}
	if !s.Allowed("a.wild.test", ip("203.0.113.9"), "") || s.Allowed("wild.test", ip("203.0.113.9"), "") {
		t.Error("wildcard allow must match subdomains only")
	}
	if !s.Allowed("staging.example.test", ip("203.0.113.9"), "https://staging.example.test/x") {
		t.Error("url prefix allow")
	}
	if !s.Allowed("", ip("203.0.113.5"), "") {
		t.Error("ip allow")
	}
	if d, _ := s.Denied("db.prod.example.test", ip("203.0.113.9"), ""); !d {
		t.Error("wildcard deny")
	}
	if _, err := NewScope([]string{"not a cidr/99"}, nil, nil); err == nil {
		t.Error("bad cidr accepted")
	}
	a := mustScope(t, []string{"b", "a"}, nil)
	b := mustScope(t, []string{"a", "b"}, nil)
	if a.Hash() != b.Hash() {
		t.Error("hash should be order independent")
	}
}

func TestLimits(t *testing.T) {
	l, raised, err := NewLimits(false, LimitRequest{})
	if err != nil || raised || l.RatePerSec != PrivateDefaults.RatePerSec {
		t.Fatalf("defaults: %+v %v %v", l, raised, err)
	}
	if _, _, err := NewLimits(true, LimitRequest{RatePerSec: PublicDefaults.RatePerSec*2 + 1}); err == nil {
		t.Fatal("raise above 2x without flag must fail")
	}
	l, raised, err = NewLimits(true, LimitRequest{RatePerSec: PublicDefaults.RatePerSec*2 + 1, AllowRaise: true})
	if err != nil || !raised || l.RatePerSec != PublicDefaults.RatePerSec*2+1 {
		t.Fatalf("raise with flag: %+v %v %v", l, raised, err)
	}
	l, raised, _ = NewLimits(true, LimitRequest{RatePerSec: 5})
	if raised || l.RatePerSec != 5 {
		t.Fatal("lowering must always be allowed")
	}
	// Rate limiter actually throttles.
	l, _, _ = NewLimits(true, LimitRequest{RatePerSec: 2})
	// burst 2 then 1 more -> ~500ms.
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.WaitConn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("rate limiter did not throttle")
	}
}

func TestDialTimeRebindingRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := &fakeResolver{hosts: map[string][]string{"rebind.test": {"127.0.0.1"}}}
	scope := mustScope(t, []string{"rebind.test"}, nil)
	d := &Dialer{Scope: scope, Resolver: res, Timeout: time.Second}
	ctx := context.Background()
	// Gate-time resolution pinned 127.0.0.1.
	addrs, err := ResolveAll(ctx, res, "rebind.test")
	if err != nil {
		t.Fatal(err)
	}
	d.Pin("rebind.test", addrs)
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("rebind.test", itoa(port)))
	if err != nil {
		t.Fatalf("first dial should succeed: %v", err)
	}
	c.Close()
	// DNS answer changes to a different (public, allow-listed) address.
	res.mu.Lock()
	res.hosts["rebind.test"] = []string{"203.0.113.77"}
	res.mu.Unlock()
	_, err = d.DialContext(ctx, "tcp", net.JoinHostPort("rebind.test", itoa(port)))
	if refusalCode(err) != CodeScopeNotAllowed {
		t.Fatalf("rebound dial must be refused, got %v", err)
	}
	// And a rebind to a denied address is refused too.
	res.mu.Lock()
	res.hosts["rebind.test"] = []string{"169.254.169.254"}
	res.mu.Unlock()
	_, err = d.DialContext(ctx, "tcp", net.JoinHostPort("rebind.test", itoa(port)))
	if !IsRefusal(err) {
		t.Fatalf("rebind to metadata must be refused, got %v", err)
	}
	// Dialing a public address during a private-limits scan is refused.
	lim, _, _ := NewLimits(false, LimitRequest{})
	d2 := &Dialer{Scope: mustScope(t, []string{"203.0.113.0/24"}, nil), Resolver: res, Limits: lim}
	_, err = d2.DialContext(ctx, "tcp", "203.0.113.5:80")
	if refusalCode(err) != CodeScopeNotAllowed {
		t.Fatalf("public dial under private limits must be refused, got %v", err)
	}
}

func TestHTTPRedirectOutOfScopeNotFollowed(t *testing.T) {
	metadataHit := false
	// A second local server stands in for the destination; it must never be hit.
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { metadataHit = true }))
	defer dest.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/meta":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/ok":
			http.Redirect(w, r, "/final", http.StatusFound)
		default:
			w.Write([]byte("final"))
		}
	}))
	defer src.Close()
	res := &fakeResolver{hosts: map[string][]string{}}
	d := &Dialer{Scope: mustScope(t, nil, nil), Resolver: res}
	client := NewHTTPClient(d, HTTPOptions{Timeout: 5 * time.Second})

	resp, err := client.Get(src.URL + "/meta")
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect to metadata endpoint must not be followed")
	}
	r, ok := AsRedirectOutOfScope(err)
	if !ok {
		t.Fatalf("want RedirectOutOfScopeError, got %T %v", err, err)
	}
	if !strings.Contains(r.To, "169.254.169.254") || refusalCode(r.Err) != CodeScopeDenied {
		t.Fatalf("unexpected redirect error: %+v", r)
	}
	if metadataHit {
		t.Fatal("destination was contacted")
	}
	// In-scope redirect is followed.
	resp, err = client.Get(src.URL + "/ok")
	if err != nil {
		t.Fatalf("in-scope redirect: %v", err)
	}
	b, _ := ReadBody(resp, 100)
	if string(b) != "final" {
		t.Fatalf("body = %q", b)
	}
	// Hop cap.
	if _, err := client.Get(src.URL + "/loop"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("redirect loop should stop at %d hops: %v", MaxRedirects, err)
	}
}

// Finding 2: a URL-prefix allow entry bounds every request the client
// sends, not only redirects. The transport refuses an out-of-prefix URL
// before any connection is attempted.
func TestURLPrefixEnforcedForEveryRequest(t *testing.T) {
	res := &fakeResolver{hosts: map[string][]string{"app.example": {"203.0.113.5"}}}
	scope := mustScope(t, []string{"https://app.example/app"}, nil)
	d := &Dialer{Scope: scope, Resolver: res, Timeout: 50 * time.Millisecond}
	d.Pin("app.example", []netip.Addr{netip.MustParseAddr("203.0.113.5")})
	c := NewHTTPClient(d, HTTPOptions{Timeout: 500 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, u := range []string{"https://app.example/.git/config", "https://app.example/", "https://app.example/application", "http://app.example/app/"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		_, err := c.Do(req)
		if refusalCode(err) != CodeScopeNotAllowed {
			t.Errorf("%s: want E_SCOPE_NOT_ALLOWED before any dial, got %v", u, err)
		}
		if n := res.callCount(); n != 0 {
			t.Errorf("%s: resolver consulted (%d) although the host is pinned", u, n)
		}
	}
	// In-prefix URLs pass the URL check; what remains is a connect error to
	// TEST-NET-3, never a refusal.
	for _, u := range []string{"https://app.example/app", "https://app.example/app/login"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		_, err := c.Do(req)
		if err == nil || IsRefusal(err) {
			t.Errorf("%s: in-prefix request must not be refused: %v", u, err)
		}
	}
	// An unpinned host is resolved for the check (and the dial re-checks).
	res.mu.Lock()
	res.hosts["other.example"] = []string{"203.0.113.9"}
	res.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://other.example/app", nil)
	if _, err := c.Do(req); refusalCode(err) != CodeScopeNotAllowed || res.callCount() == 0 {
		t.Errorf("unpinned public host outside allow: %v (resolver calls %d)", err, res.callCount())
	}
}

// Finding 3: quoted keys, the shape of API responses and config dumps, are
// redacted with the key visible and the value masked per the Mask budget.
func TestRedactorQuotedKeys(t *testing.T) {
	r := NewRedactor()
	cases := []struct{ in, keep, gone string }{
		{`{"password": "hunter2-not-a-real-pw", "Token": "abcdefghijklmnopqrstuv", "api_key": "zzzzzzzzzzzzzzzz"}`, `"password": "`, "hunter2-not-a-real-pw"},
		{`{"Token": "abcdefghijklmnopqrstuv"}`, `"Token": "`, "abcdefghijklmnopqrstuv"},
		{`{"api_key":"zzzzzzzzzzzzzzzz"}`, `"api_key":"`, "zzzzzzzzzzzzzzzz"},
		{`{"apiKey": "k1k2k3k4k5k6k7k8"}`, `"apiKey": "`, "k1k2k3k4k5k6k7k8"},
		{`{"api-key": "k1k2k3k4k5k6k7k8"}`, `"api-key": "`, "k1k2k3k4k5k6k7k8"},
		{`{"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`, `"SecretAccessKey": "`, "wJalrXUtnFEMI/K7MDENG"},
		{`{"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`, `"aws_secret_access_key": "`, "K7MDENG"},
		{`{"authorization": "Basic dXNlcjpwYXNzd29yZA=="}`, `"authorization": "`, "dXNlcjpwYXNzd29yZA"},
		{`{"db_password": "correct-horse-battery"}`, `"db_password": "`, "horse-battery"},
		{`{"client_secret": "s3cr3t-value-here"}`, `"client_secret": "`, "s3cr3t-value"},
		{`{"passwd": "short1"}`, `"passwd": "`, "short1"},
		{`{"pwd": "pwdvalue12"}`, `"pwd": "`, "pwdvalue12"},
		// Nested object.
		{`{"user": {"name": "bob", "auth": {"password": "nested-secret-value"}}}`, `"name": "bob", "auth": {"password": "`, "nested-secret-value"},
		// Single quotes, mixed quotes.
		{`{'password': 'single-quoted-secret'}`, `'password': '`, "single-quoted-secret"},
		{`{"password": 'mixed-quoted-secret'}`, `"password": '`, "mixed-quoted-secret"},
		// Escaped quotes inside the value stay inside the mask.
		{`{"password": "ab\"cd\"efghijklmnop"}`, `"password": "`, `cd\"ef`},
		// Whitespace variants.
		{`{ "secret" :   "spaced-out-secret-value" }`, `"secret" :   "`, "spaced-out-secret-value"},
		// Multiple keys on one line are each masked independently.
		{`{"token":"first-token-value","password":"second-pw-value"}`, `"password":"`, "second-pw-value"},
	}
	for _, c := range cases {
		out := r.Redact(c.in)
		if out == c.in {
			t.Errorf("not redacted: %s", c.in)
			continue
		}
		if !strings.Contains(out, c.keep) {
			t.Errorf("%s -> %s lost key context %q", c.in, out, c.keep)
		}
		if strings.Contains(out, c.gone) {
			t.Errorf("%s -> %s still contains %q", c.in, out, c.gone)
		}
		if strings.Count(out, "{") != strings.Count(c.in, "{") || strings.Count(out, "}") != strings.Count(c.in, "}") {
			t.Errorf("structure damaged: %s -> %s", c.in, out)
		}
	}
	// Mask budget applies: a 22-char value reveals at most 5 (n/4) characters.
	out := r.Redact(`{"Token": "abcdefghijklmnopqrstuv"}`)
	if visible := strings.Count(strings.TrimPrefix(strings.TrimSuffix(out, `"}`), `{"Token": "`), "*"); visible == 0 {
		t.Errorf("value not masked: %s", out)
	}
	if strings.Contains(out, "abcdefg") {
		t.Errorf("more than the budget revealed: %s", out)
	}
	// Non-secret quoted keys and unquoted values are untouched.
	for _, keep := range []string{`{"username": "bob", "token_type": "Bearer"}`, `{"count": 12, "has_password": true}`, `{"tokens": ["a", "b"]}`} {
		if got := r.Redact(keep); got != keep {
			t.Errorf("false positive: %s -> %s", keep, got)
		}
	}
	// Existing unquoted shapes still work alongside.
	if got := r.Redact(`password: hunter2-not-a-real-pw and {"password": "hunter2-not-a-real-pw"}`); strings.Contains(got, "hunter2-not-a-real-pw") {
		t.Errorf("mixed shapes: %s", got)
	}
	// Large hostile input stays linear (RE2): ~230 KiB of quote soup with no
	// closing quote, the classic backtracking trigger.
	soup := strings.Repeat(`{"password": "`+strings.Repeat(`\"`, 50)+`x`, 2000)
	start := time.Now()
	_ = r.Redact(soup)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("redaction took %s on %d bytes", d, len(soup))
	}
}

func TestRedactor(t *testing.T) {
	r := NewRedactor()
	cases := map[string]string{
		"key AKIAIOSFODNN7EXAMPLE here":                    "AKIA",
		"token ghp_abcdefghijklmnopqrstuvwxyz0123456789 x": "ghp_",
		"password=SuperSecret123!":                         "password=",
		"https://user:p4ssw0rd@db.example/x":               "user:***@",
	}
	for in, keep := range cases {
		out := r.Redact(in)
		if out == in {
			t.Errorf("not redacted: %q", in)
		}
		if !strings.Contains(out, keep) {
			t.Errorf("%q -> %q lost context %q", in, out, keep)
		}
	}
	if got := r.Redact("AKIAIOSFODNN7EXAMPLE"); strings.Contains(got, "IOSFODNN7EXAM") {
		t.Errorf("value still visible: %q", got)
	}
	if got := Mask("AKIAIOSFODNN7EXAMPLE"); !strings.HasPrefix(got, "AKIA") || !strings.HasSuffix(got, "E") || strings.Contains(got, "IOSFODNN") {
		t.Errorf("Mask = %q", got)
	}
	if Mask("short") != "*****" {
		t.Errorf("short values fully masked: %q", Mask("short"))
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	ev := SecretEvidence(key, "file", "a.py:1", "AKIAIOSFODNN7EXAMPLE")
	if ev.Redacted != Mask("AKIAIOSFODNN7EXAMPLE") || ev.Hash != SecretHash(key, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("SecretEvidence = %+v", ev)
	}
	if StripControl("a\x00b\x1b[31mc\n") != "ab[31mc\n" {
		t.Error("StripControl")
	}
	te := r.TextEvidence("banner", "h:1", strings.Repeat("x", 10000))
	if len(te.Redacted) != domain.MaxEvidenceBytes {
		t.Errorf("evidence not capped: %d", len(te.Redacted))
	}
}

// Finding 4: a mask must never leak enough of a short value to reconstruct
// it, and the fingerprint must be keyed (stable per key, different across keys,
// not equal to a plain digest).
func TestMaskBudgetAndKeyedSecretHash(t *testing.T) {
	revealed := func(raw, masked string) int {
		n := 0
		for _, c := range masked {
			if c != '*' {
				n++
			}
		}
		if len(masked) > 0 && !strings.Contains(masked, "*") {
			t.Fatalf("Mask(%q) = %q has no masking", raw, masked)
		}
		return n
	}
	for _, raw := range []string{"Hunter2!", "Hunter2!x", "correct-horse", "AKIAIOSFODNN7EXAMPLE", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", strings.Repeat("Z", 200)} {
		m := Mask(raw)
		got := revealed(raw, m)
		limit := len(raw) / 4
		if limit > MaskMaxReveal {
			limit = MaskMaxReveal
		}
		if len(raw) < MaskShortLen {
			limit = 2
		}
		if got > limit {
			t.Errorf("Mask(%q) = %q reveals %d chars, limit %d", raw, m, got, limit)
		}
		if strings.Contains(m, "unter2") || strings.Contains(m, "horse") {
			t.Errorf("Mask(%q) = %q leaks the value", raw, m)
		}
	}
	if Mask("1234567") != "*******" {
		t.Errorf("values under 8 chars must be fully masked: %q", Mask("1234567"))
	}
	k1 := []byte("key-one-key-one-key-one-key-one!")
	k2 := []byte("key-two-key-two-key-two-key-two!")
	h1 := SecretHash(k1, "Hunter2!")
	if h1 != SecretHash(append([]byte(nil), k1...), "Hunter2!") {
		t.Error("hash must be deterministic for one key")
	}
	if SecretHash(k1, "Hunter2!") == SecretHash(k2, "Hunter2!") {
		t.Error("hash must differ across keys")
	}
	if SecretHash(k1, "Hunter2!") == domain.SHA256Hex("Hunter2!") {
		t.Error("hash must not be an unkeyed digest")
	}
}

// Finding 3: URL-prefix allow entries compare parsed components, so a
// hostname that merely starts with the entry, or userinfo tricks, never match.
func TestURLPrefixEntryComponentMatch(t *testing.T) {
	s := mustScope(t, []string{"https://staging.example.com", "https://api.example.com:8443/v1/"}, nil)
	pub := []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	bypass := []struct{ host, url string }{
		{"staging.example.com.evil.net", "https://staging.example.com.evil.net/"},
		{"evil.net", "https://staging.example.com@evil.net/"},
		{"evil.net", "https://staging.example.com:x@evil.net/"},
		{"staging.example.com", "http://staging.example.com/"},                   // scheme differs
		{"api.example.com", "https://api.example.com:9443/v1/x"},                 // port differs
		{"api.example.com", "https://api.example.com:8443/v1x"},                  // not on a segment boundary
		{"api.example.com", "https://api.example.com:8443/v2/"},                  // other path
		{"staging.example.com", "https://staging.example.com@evil.net/"},         // userinfo on the right host string
		{"staging.example.com", "https://user:pw@staging.example.com/"},          // credentials never match
		{"staging.example.com", "https://staging.example.com.evil.net/x"},        // host mismatch even with matching label
		{"staging.example.com", "https://xstaging.example.com/"},                 // host mismatch
		{"staging.example.com", "https://staging.example.com.evil.net:443/path"}, // host mismatch with port
	}
	for _, c := range bypass {
		if _, err := s.Check(c.host, pub, c.url); err == nil {
			t.Errorf("BYPASS: %s admitted", c.url)
		}
	}
	legit := []struct{ host, url string }{
		{"staging.example.com", "https://staging.example.com"},
		{"staging.example.com", "https://staging.example.com/"},
		{"STAGING.example.com", "https://STAGING.Example.com/login?x=1"},
		{"staging.example.com", "https://staging.example.com:443/deep/path"},
		{"api.example.com", "https://api.example.com:8443/v1"},
		{"api.example.com", "https://api.example.com:8443/v1/users/1"},
	}
	for _, c := range legit {
		if _, err := s.Check(c.host, pub, c.url); err != nil {
			t.Errorf("legit %s refused: %v", c.url, err)
		}
	}
	if _, err := NewScope([]string{"https://u:p@staging.example.com"}, nil, nil); err == nil {
		t.Error("allow entry with credentials must be rejected at load")
	}
}

// Finding 1: once a public target is pinned, redirects and dials into
// loopback/private/link-local/ULA space are refused. A private-only scan is
// unaffected.
func TestPublicScanNeverReachesPrivateAddresses(t *testing.T) {
	res := &fakeResolver{hosts: map[string][]string{
		"app.example.com": {"203.0.113.10"},
		"attacker.tld":    {"10.0.0.5"},
		"intranet.test":   {"10.1.2.3"},
	}}
	s := mustScope(t, []string{"app.example.com", "attacker.tld"}, nil)
	d := &Dialer{Scope: s, Resolver: res, Timeout: time.Second}
	d.Pin("app.example.com", []netip.Addr{netip.MustParseAddr("203.0.113.10")})
	if !d.PinnedPublic() {
		t.Fatal("public pin not recorded")
	}
	c := NewHTTPClient(d, HTTPOptions{})
	from, _ := http.NewRequest("GET", "https://app.example.com/", nil)
	targets := []string{
		"http://127.0.0.1:6379/", "http://10.0.0.1/cgi-bin/reboot", "http://[::1]:9200/_cat",
		"http://169.254.170.2/v2/credentials/x", "http://169.254.169.254/latest/", "http://attacker.tld/admin",
		"http://192.168.1.1/", "http://[fd12::1]/", "http://172.16.0.1/",
	}
	for _, to := range targets {
		req, _ := http.NewRequest("GET", to, nil)
		err := c.CheckRedirect(req, []*http.Request{from})
		if err == nil {
			t.Errorf("FOLLOWED: public target redirected scanner to %s", to)
			continue
		}
		r, ok := AsRedirectOutOfScope(err)
		if !ok || !IsRefusal(r.Err) {
			t.Errorf("redirect to %s: want RedirectOutOfScopeError wrapping a refusal, got %T %v", to, err, err)
		}
	}
	// The ECS credential endpoint is denied outright (built-in), not merely non-public.
	req, _ := http.NewRequest("GET", "http://169.254.170.2/v2/credentials/x", nil)
	if r, _ := AsRedirectOutOfScope(c.CheckRedirect(req, []*http.Request{from})); refusalCode(r.Err) != CodeScopeDenied {
		t.Errorf("ECS endpoint should hit the built-in deny list: %v", r)
	}
	// Direct dials from the same scan are refused too (no connection attempted).
	for _, addr := range []string{"127.0.0.1:6379", "10.0.0.1:80", "[::1]:9200", "attacker.tld:80"} {
		if _, err := d.DialContext(context.Background(), "tcp", addr); refusalCode(err) != CodeScopeNotAllowed && refusalCode(err) != CodeScopeDenied {
			t.Errorf("dial %s during public scan: want refusal, got %v", addr, err)
		}
	}
	// A pinned private target in the same scan is still allowed through the pin check.
	d.Pin("intranet.test", []netip.Addr{netip.MustParseAddr("10.1.2.3")})
	if err := d.checkPinned("intranet.test", []netip.Addr{netip.MustParseAddr("10.1.2.3")}); err != nil {
		t.Errorf("pinned private target refused: %v", err)
	}
	// Redirect to an in-scope public host remains allowed.
	okReq, _ := http.NewRequest("GET", "https://app.example.com/next", nil)
	if err := c.CheckRedirect(okReq, []*http.Request{from}); err != nil {
		t.Errorf("in-scope public redirect refused: %v", err)
	}
	// Private-only scan: redirect into private space keeps working.
	dp := &Dialer{Scope: mustScope(t, nil, nil), Resolver: res}
	dp.Pin("intranet.test", []netip.Addr{netip.MustParseAddr("10.1.2.3")})
	cp := NewHTTPClient(dp, HTTPOptions{})
	fromP, _ := http.NewRequest("GET", "http://intranet.test/", nil)
	toP, _ := http.NewRequest("GET", "http://10.0.0.1/", nil)
	if err := cp.CheckRedirect(toP, []*http.Request{fromP}); err != nil {
		t.Errorf("private scan redirect to private address should be allowed: %v", err)
	}
}

func TestVerifyTokenAndCheck(t *testing.T) {
	home := t.TempDir()
	secret, err := LoadOrCreateSecret(home)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := LoadOrCreateSecret(home)
	if string(secret) != string(again) {
		t.Fatal("secret must persist")
	}
	tok := Token(secret, "Example.test")
	if tok != Token(secret, "example.test.") || len(tok) != 32 {
		t.Fatalf("token not deterministic/normalised: %q", tok)
	}
	if tok == Token([]byte("other secret................."), "example.test") {
		t.Fatal("token must depend on secret")
	}

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	res := &fakeResolver{hosts: map[string][]string{}, txt: map[string][]string{
		"_scnr-verify.example.test": {"v=spf1 -all", VerifyRecordPrefix + tok},
	}}
	v := &Verifier{Store: st, Secret: secret, TXT: res, Now: func() time.Time { return now }}
	method, err := v.Check(context.Background(), "example.test")
	if err != nil || method != domain.ConsentDNSTXT {
		t.Fatalf("dns check: %v %v", method, err)
	}
	rec, err := st.GetVerification(context.Background(), "example.test")
	if err != nil || !rec.ExpiresAt.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("verification row: %+v %v", rec, err)
	}
	ok, _ := v.IsVerified(context.Background(), "example.test")
	if !ok {
		t.Fatal("should be verified")
	}
	if ok, _ := v.IsVerified(context.Background(), "sub.deep.example.test"); !ok {
		t.Fatal("DNS verification should cover subdomains")
	}
	if ok, _ := v.IsVerified(context.Background(), "other.test"); ok {
		t.Fatal("unrelated host verified")
	}
	v.Now = func() time.Time { return now.Add(31 * 24 * time.Hour) }
	if ok, _ := v.IsVerified(context.Background(), "example.test"); ok {
		t.Fatal("expired verification accepted")
	}
	// Well-known over HTTP on a bare IP, served by a local test server.
	v.Now = func() time.Time { return now }
	wk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == VerifyWellKnownPath {
			w.Write([]byte(VerifyRecordPrefix + Token(secret, "127.0.0.1") + "\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer wk.Close()
	// The verifier hits https then http on port 80 by default; point the
	// client at the test server by rewriting the host via a custom transport.
	v.HTTP = &http.Client{Transport: rewriteTransport{base: wk.Client().Transport, to: wk.Listener.Addr().String()}}
	method, err = v.Check(context.Background(), "127.0.0.1")
	if err != nil || method != domain.ConsentWellKnown {
		t.Fatalf("well-known check: %v %v", method, err)
	}
	if ok, _ := v.IsVerified(context.Background(), "127.0.0.1"); !ok {
		t.Fatal("ip should be verified")
	}
	// Failure path: nothing published.
	if _, err := v.Check(context.Background(), "nothing.test"); err == nil {
		t.Fatal("unpublished token must fail")
	}
}

type rewriteTransport struct {
	base http.RoundTripper
	to   string
}

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = r.to
	return r.base.RoundTrip(req)
}

func TestHosts(t *testing.T) {
	h := Hosts(netip.MustParsePrefix("10.0.0.0/30"))
	if len(h) != 2 || h[0].String() != "10.0.0.1" || h[1].String() != "10.0.0.2" {
		t.Fatalf("hosts /30 = %v", h)
	}
	if n := len(Hosts(netip.MustParsePrefix("10.0.0.0/24"))); n != 254 {
		t.Fatalf("/24 = %d", n)
	}
	if n := len(Hosts(netip.MustParsePrefix("10.0.0.5/32"))); n != 1 {
		t.Fatalf("/32 = %d", n)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
