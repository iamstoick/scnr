package netscan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

func testOptions(t *testing.T, ports []int) engine.Options {
	t.Helper()
	scope, err := safety.NewScope(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	limits, _, _ := safety.NewLimits(false, safety.LimitRequest{})
	d := &safety.Dialer{Scope: scope, Limits: limits}
	p, _ := engine.ProfileByName("quick")
	return engine.Options{Profile: p, Limiter: limits, Scope: scope, Dialer: d, HTTP: safety.NewHTTPClient(d, safety.HTTPOptions{Timeout: 3 * time.Second}), Ports: ports, Redactor: safety.NewRedactor()}
}

func portOf(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

func collect(t *testing.T, e *Engine, tgt domain.Target, o engine.Options) map[string][]domain.Finding {
	t.Helper()
	out := map[string][]domain.Finding{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.Run(ctx, tgt, o, func(f domain.Finding) error { out[f.RuleID] = append(out[f.RuleID], f); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScanLocalListeners(t *testing.T) {
	// Plain HTTP listener.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fixture/1.0")
		w.Write([]byte("<html><head><title>Fixture App</title></head></html>"))
	}))
	defer httpSrv.Close()
	// Self-signed TLS listener (httptest's cert is self-signed, for "example.com").
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer tlsSrv.Close()
	// Raw banner listener (SSH-like).
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
			c.Write([]byte("SSH-2.0-fixture\r\n"))
			c.Close()
		}
	}()
	// A closed port.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := portOf(closed.Addr().String())
	closed.Close()

	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if len(e.top1000) != 1000 {
		t.Fatalf("embedded port list has %d entries", len(e.top1000))
	}
	// The TLS server's port is not in tlsPorts; force TLS detection by using
	// the httptest listener's actual port and a tiny override: ports ending
	// in 443 are probed for TLS, so bind a second listener on such a port if
	// possible, else rely on the self-signed server being on an arbitrary
	// port and probe it via tlsPorts table injection.
	tlsPort := portOf(tlsSrv.Listener.Addr().String())
	tlsPorts[tlsPort] = true
	defer delete(tlsPorts, tlsPort)
	httpPort := portOf(httpSrv.Listener.Addr().String())
	httpPorts[httpPort] = true
	defer delete(httpPorts, httpPort)

	ports := []int{httpPort, tlsPort, portOf(ln.Addr().String()), closedPort}
	tgt := domain.Target{Raw: "127.0.0.1", Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}
	o := testOptions(t, ports)
	plan, err := e.Plan(context.Background(), tgt, o)
	if err != nil || plan.EstRequests != len(ports) || !plan.Network {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	out := collect(t, e, tgt, o)

	open := out["net.open-port"]
	if len(open) != 3 {
		t.Fatalf("want 3 open ports, got %d: %+v", len(open), open)
	}
	titles := map[int]string{}
	for _, f := range open {
		titles[portOf(f.Location)] = f.Title
		if f.AssetKey != "host:127.0.0.1" || f.Confidence != domain.Confirmed {
			t.Errorf("open-port finding %+v", f)
		}
	}
	if titles[httpPort] != "Open TCP port "+strconv.Itoa(httpPort)+` (http fixture/1.0 "Fixture App")` {
		t.Errorf("http title = %q", titles[httpPort])
	}
	if titles[portOf(ln.Addr().String())] != "Open TCP port "+strconv.Itoa(portOf(ln.Addr().String()))+" (ssh)" {
		t.Errorf("banner title = %q", titles[portOf(ln.Addr().String())])
	}
	if len(out["net.tls.self-signed"]) != 1 {
		t.Fatalf("want net.tls.self-signed, got %v", out)
	}
	if len(out["net.tls.hostname-mismatch"]) != 0 {
		t.Errorf("httptest cert carries a 127.0.0.1 SAN; no hostname mismatch expected: %v", out["net.tls.hostname-mismatch"])
	}
	if len(out["net.tls.legacy-version"]) != 0 {
		t.Errorf("Go's test server does not offer TLS 1.0/1.1: %v", out["net.tls.legacy-version"])
	}
	ev := out["net.tls.self-signed"][0].Evidence
	if len(ev) == 0 || ev[0].Kind != "cert" {
		t.Errorf("tls evidence = %+v", ev)
	}
}

func TestTLSLegacyAndExpired(t *testing.T) {
	// A server that only speaks TLS 1.0 with an expired cert.
	cert := selfSignedCert(t, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10})
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
			go func(c net.Conn) {
				c.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					tc.Handshake()
				}
				c.Close()
			}(c)
		}
	}()
	port := portOf(ln.Addr().String())
	tlsPorts[port] = true
	defer delete(tlsPorts, port)
	e, _ := New()
	// Pretend "now" is far in the future so the fixture cert is expired.
	e.now = func() time.Time { return time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) }
	e.roots = x509.NewCertPool() // no trust -> self-signed path also exercised
	tgt := domain.Target{Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	out := collect(t, e, tgt, o)
	if len(out["net.tls.expired"]) != 1 {
		t.Errorf("want expired, got %v", out)
	}
	legacy := out["net.tls.legacy-version"]
	if len(legacy) != 1 || legacy[0].Title != "Legacy TLS version accepted (TLS 1.0)" {
		t.Errorf("want one TLS 1.0 legacy finding, got %+v", legacy)
	}
}

func TestRedirectOutOfScopeEmitsFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	port := portOf(srv.Listener.Addr().String())
	httpPorts[port] = true
	defer delete(httpPorts, port)
	e, _ := New()
	tgt := domain.Target{Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}
	out := collect(t, e, tgt, testOptions(t, []int{port}))
	r := out["web.redirect-out-of-scope"]
	if len(r) != 1 {
		t.Fatalf("want redirect finding, got %v", out)
	}
	if len(r[0].Evidence) != 1 || r[0].Evidence[0].Redacted != "Location: http://169.254.169.254/latest/meta-data/" {
		t.Fatalf("evidence = %+v", r[0].Evidence)
	}
	if len(out["net.open-port"]) != 1 {
		t.Fatalf("open port still reported: %v", out)
	}
}

func TestAdminAndDBPortSeverity(t *testing.T) {
	e, _ := New()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
	port := portOf(ln.Addr().String())
	dbPorts[port] = "redis"
	defer delete(dbPorts, port)
	adminPorts[port] = "vnc"
	defer delete(adminPorts, port)
	tgt := domain.Target{Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}
	o := testOptions(t, []int{port})
	o.HTTP = nil
	out := collect(t, e, tgt, o)
	if f := out["net.exposed-db-port"]; len(f) != 1 || f[0].Severity != domain.Medium {
		t.Fatalf("private db port should be medium: %+v", f)
	}
	if f := out["net.exposed-admin-port"]; len(f) != 1 || f[0].Severity != domain.Medium {
		t.Fatalf("private admin port should be medium: %+v", f)
	}
	tgt.Public = true
	out = collect(t, e, tgt, o)
	if f := out["net.exposed-db-port"]; f[0].Severity != domain.High {
		t.Fatalf("public db port should be high: %+v", f)
	}
}

func TestParsePorts(t *testing.T) {
	e, _ := New()
	p, err := e.ParsePorts("22,80,8000-8002")
	if err != nil || len(p) != 5 || p[4] != 8002 {
		t.Fatalf("%v %v", p, err)
	}
	if p, _ := e.ParsePorts("top100"); len(p) != 100 {
		t.Fatal("top100")
	}
	if p, _ := e.ParsePorts("all"); len(p) != 65535 {
		t.Fatal("all")
	}
	for _, bad := range []string{"0", "70000", "80-22", "x"} {
		if _, err := e.ParsePorts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !e.Supports(domain.Target{Type: domain.TargetCIDR}) || e.Supports(domain.Target{Type: domain.TargetPath}) {
		t.Fatal("Supports")
	}
}

func TestCIDRHostCapHonoured(t *testing.T) {
	e, _ := New()
	o := testOptions(t, []int{1})
	o.Limiter.MaxHosts = 3
	hosts, err := e.hosts(domain.Target{Type: domain.TargetCIDR, Value: "127.0.0.0/24"}, o)
	if err != nil || len(hosts) != 3 {
		t.Fatalf("%v %v", hosts, err)
	}
}

func TestRequiresDialer(t *testing.T) {
	e, _ := New()
	if err := e.Run(context.Background(), domain.Target{Type: domain.TargetHost, Value: "127.0.0.1"}, engine.Options{}, nil); err == nil {
		t.Fatal("netscan must refuse to run without the scope-checked dialer")
	}
}

// rebindResolver answers with first[] until flipAfter lookups have happened,
// then with then[] (DNS rebinding between the port connect and the TLS probe).
type rebindResolver struct {
	mu        sync.Mutex
	host      string
	first     []string
	then      []string
	flipAfter int
	calls     int
}

func (r *rebindResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if host != r.host {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	r.calls++
	ips := r.first
	if r.calls > r.flipAfter {
		ips = r.then
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// countingTLSListener accepts TLS connections and counts them.
func countingTLSListener(t *testing.T) (port int, count *int32) {
	t.Helper()
	cert := selfSignedCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&n, 1)
			go func(c net.Conn) {
				c.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					tc.Handshake()
				}
				c.Close()
			}(c)
		}
	}()
	return portOf(ln.Addr().String()), &n
}

// Finding 2: the TLS probes must go through the scope-checked dialer. A
// resolver that answers 127.0.0.1 for the first (port) connect and then
// rebinds to a metadata/RFC1918 address must see no TLS handshake at all.
// Before the fix, checkTLS/offersVersion used a raw net.Dialer on the
// hostname (system DNS for "localhost"), so the listener saw 3 extra
// connections.
func TestTLSProbesUseSafeDialer(t *testing.T) {
	for _, rebindTo := range []string{"169.254.169.254", "10.0.0.1"} {
		t.Run(rebindTo, func(t *testing.T) {
			port, conns := countingTLSListener(t)
			tlsPorts[port] = true
			defer delete(tlsPorts, port)
			res := &rebindResolver{host: "localhost", first: []string{"127.0.0.1"}, then: []string{rebindTo}, flipAfter: 1}
			scope, _ := safety.NewScope(nil, nil)
			limits, _, _ := safety.NewLimits(false, safety.LimitRequest{})
			d := &safety.Dialer{Scope: scope, Resolver: res, Limits: limits}
			d.Pin("localhost", []netip.Addr{netip.MustParseAddr("127.0.0.1")})
			p, _ := engine.ProfileByName("quick")
			o := engine.Options{Profile: p, Limiter: limits, Scope: scope, Dialer: d, Ports: []int{port}, Redactor: safety.NewRedactor()}
			e, _ := New()
			tgt := domain.Target{Type: domain.TargetHost, Value: "localhost", Hostname: "localhost"}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err := e.Run(ctx, tgt, o, func(domain.Finding) error { return nil })
			if !safety.IsRefusal(err) {
				t.Fatalf("rebound TLS probe must surface a refusal, got %v", err)
			}
			if got := atomic.LoadInt32(conns); got != 1 {
				t.Fatalf("listener saw %d connections; only the pinned port connect is allowed", got)
			}
			if res.calls < 2 {
				t.Fatalf("TLS probe did not resolve through the safe dialer (resolver calls = %d)", res.calls)
			}
		})
	}
}

// Finding 2 (rate limiting): every TLS probe connection counts against the
// connection limiter. One TLS port costs 1 connect + 1 handshake + 2 legacy
// version probes = 4 tokens; at 2 conn/s with burst 2 that is >= ~1s.
func TestTLSProbesCountAgainstConnLimiter(t *testing.T) {
	port, conns := countingTLSListener(t)
	tlsPorts[port] = true
	defer delete(tlsPorts, port)
	o := testOptions(t, []int{port})
	o.HTTP = nil
	limits, _, _ := safety.NewLimits(false, safety.LimitRequest{RatePerSec: 2})
	o.Limiter = limits
	o.Dialer = &safety.Dialer{Scope: o.Scope, Limits: limits}
	e, _ := New()
	start := time.Now()
	collect(t, e, domain.Target{Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}, o)
	if got := atomic.LoadInt32(conns); got != 4 {
		t.Fatalf("expected 4 connections (connect + handshake + 2 version probes), got %d", got)
	}
	if el := time.Since(start); el < 600*time.Millisecond {
		t.Fatalf("4 connections at 2 conn/s finished in %v; TLS probes bypassed the limiter", el)
	}
}

// selfSignedCert generates an in-memory self-signed certificate.
func selfSignedCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
