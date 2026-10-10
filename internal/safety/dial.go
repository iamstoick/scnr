package safety

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Dialer resolves and re-checks scope at connect time, then dials the
// checked IP (never the hostname) so DNS rebinding cannot swap the address
// between check and connect.
type Dialer struct {
	Scope    *Scope
	Resolver Resolver
	Limits   *Limits
	Timeout  time.Duration
	// RequireAllow makes every destination, private ones included, match an
	// allow entry (NewEndpointClient: the allow list is a fixed set of
	// declared hosts, not a scan scope where private space is implicitly
	// in bounds).
	RequireAllow bool

	pins *pinSet
}

type pinSet struct {
	mu     sync.Mutex
	pinned map[string][]netip.Addr
	// public is set once any pinned target resolved to a public address.
	// From then on the dialer refuses private/loopback/link-local
	// destinations that are not themselves pinned targets: a public site
	// must not be able to redirect the scanner into the operator's LAN.
	public bool
}

// WithTimeout returns a dialer sharing scope, resolver, limits and pins but
// with a different connect timeout.
func (d *Dialer) WithTimeout(t time.Duration) *Dialer {
	d.ensurePins()
	return &Dialer{Scope: d.Scope, Resolver: d.Resolver, Limits: d.Limits, Timeout: t, RequireAllow: d.RequireAllow, pins: d.pins}
}

func (d *Dialer) ensurePins() {
	if d.pins == nil {
		d.pins = &pinSet{pinned: map[string][]netip.Addr{}}
	}
}

// Pin records the addresses the gate resolved for host. A later dial whose
// answer is not a subset of the pinned set is refused (DNS rebinding).
func (d *Dialer) Pin(host string, addrs []netip.Addr) {
	d.ensurePins()
	d.pins.mu.Lock()
	defer d.pins.mu.Unlock()
	d.pins.pinned[strings.ToLower(strings.TrimSuffix(host, "."))] = append([]netip.Addr(nil), addrs...)
	for _, a := range addrs {
		if !IsPrivate(a) {
			d.pins.public = true
		}
	}
}

// Pinned returns the addresses recorded for host at authorisation time (nil
// when none). Adapters that cannot use the dialer pass these to the tool so
// it scans exactly the authorised addresses, not a fresh DNS answer.
func (d *Dialer) Pinned(host string) []netip.Addr {
	if d == nil || d.pins == nil {
		return nil
	}
	d.pins.mu.Lock()
	defer d.pins.mu.Unlock()
	return append([]netip.Addr(nil), d.pins.pinned[strings.ToLower(strings.TrimSuffix(host, "."))]...)
}

// PinnedPublic reports whether any pinned target is public.
func (d *Dialer) PinnedPublic() bool {
	if d.pins == nil {
		return false
	}
	d.pins.mu.Lock()
	defer d.pins.mu.Unlock()
	return d.pins.public
}

// checkPinned enforces both pin rules: a pinned host must still resolve
// within its pinned set (DNS rebinding), and once a public target has been
// pinned, non-public destinations are refused unless they are pinned
// targets themselves (redirect/rebind into loopback, RFC1918, link-local,
// ULA from a public scan).
func (d *Dialer) checkPinned(host string, ips []netip.Addr) error {
	if d.pins == nil {
		return nil
	}
	d.pins.mu.Lock()
	pinned, ok := d.pins.pinned[strings.ToLower(strings.TrimSuffix(host, "."))]
	public := d.pins.public
	d.pins.mu.Unlock()
	if !ok {
		if public && AnyPrivate(ips) {
			return &RefusalError{Code: CodeScopeNotAllowed, Target: host,
				Reason: fmt.Sprintf("resolves to a non-public address (%v) during a public-target scan", ips)}
		}
		return nil
	}
	for _, ip := range ips {
		found := false
		for _, p := range pinned {
			if p == ip {
				found = true
				break
			}
		}
		if !found {
			return &RefusalError{Code: CodeScopeNotAllowed, Target: host,
				Reason: fmt.Sprintf("DNS answer changed since authorisation (%s not in %v); possible rebinding", ip, pinned)}
		}
	}
	return nil
}

// check runs the scope check plus the RequireAllow rule.
func (d *Dialer) check(host string, ips []netip.Addr, rawURL string) (bool, error) {
	public, err := d.Scope.Check(host, ips, rawURL)
	if err != nil {
		return public, err
	}
	if d.RequireAllow && !d.Scope.Allowed(host, ips, rawURL) {
		return public, &RefusalError{Code: CodeScopeNotAllowed, Target: host, Reason: "not a declared endpoint host"}
	}
	return public, nil
}

// DialContext implements the net.Dialer contract for "tcp" networks.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := ResolveAll(ctx, d.Resolver, host)
	if err != nil {
		return nil, &RefusalError{Code: CodeUnresolvable, Target: addr, Reason: err.Error()}
	}
	public, err := d.check(host, ips, "")
	if err != nil {
		return nil, err
	}
	if err := d.checkPinned(host, ips); err != nil {
		return nil, err
	}
	if d.Limits != nil {
		if d.Limits.Public != public && public {
			// A private scan reached a public address at dial time: refuse.
			return nil, &RefusalError{Code: CodeScopeNotAllowed, Target: addr, Reason: "resolved to a public address during a private-scope scan"}
		}
		if err := d.Limits.WaitConn(ctx); err != nil {
			return nil, err
		}
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	nd := &net.Dialer{Timeout: timeout}
	var lastErr error
	for _, ip := range ips {
		c, err := nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// CheckURL applies the full scope check to one HTTP request URL: deny,
// private/allow (URL-prefix allow entries are matched by scheme, host, port
// and path here, which a bare dial cannot do), and the pin rules. The
// addresses used are the gate-pinned ones when the host is pinned, else a
// fresh resolution; DialContext re-resolves and detects rebinding anyway.
func (d *Dialer) CheckURL(ctx context.Context, u *url.URL) error {
	host := u.Hostname()
	ips := d.Pinned(host)
	if len(ips) == 0 {
		var err error
		if ips, err = ResolveAll(ctx, d.Resolver, host); err != nil {
			return &RefusalError{Code: CodeUnresolvable, Target: host, Reason: err.Error()}
		}
	}
	if _, err := d.check(host, ips, u.String()); err != nil {
		return err
	}
	return d.checkPinned(host, ips)
}

// RedirectOutOfScopeError is returned (wrapped in *url.Error) when a redirect
// points outside scope. Callers turn it into web.redirect-out-of-scope.
type RedirectOutOfScopeError struct {
	From string
	To   string
	Err  error
}

func (e *RedirectOutOfScopeError) Error() string {
	return fmt.Sprintf("redirect from %s to %s refused: %v", e.From, e.To, e.Err)
}

func (e *RedirectOutOfScopeError) Unwrap() error { return e.Err }

// AsRedirectOutOfScope extracts the typed error from a client error chain.
func AsRedirectOutOfScope(err error) (*RedirectOutOfScopeError, bool) {
	var r *RedirectOutOfScopeError
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

// MaxRedirects is the hop cap.
const MaxRedirects = 5

// HTTPOptions configure NewHTTPClient.
type HTTPOptions struct {
	Timeout   time.Duration
	UserAgent string
}

// NewHTTPClient returns a client whose every connection (including each
// redirect hop) passes the scope check, with per-host HTTP rate limiting.
// TLS verification stays on: the client is used to observe targets, and
// TLS weaknesses are reported by netscan's dedicated handshake checks.
func NewHTTPClient(d *Dialer, o HTTPOptions) *http.Client {
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "scnr"
	}
	tr := &http.Transport{
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  o.Timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
		Proxy:                  nil, // scanning traffic never uses HTTP_PROXY
	}
	return &http.Client{
		Timeout:   o.Timeout,
		Transport: &limitedTransport{rt: tr, dialer: d, ua: o.UserAgent},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", MaxRedirects)
			}
			if err := d.CheckURL(req.Context(), req.URL); err != nil {
				return &RedirectOutOfScopeError{From: via[len(via)-1].URL.String(), To: req.URL.String(), Err: err}
			}
			return nil
		},
	}
}

// limitedTransport is the single choke point for every HTTP request the
// client sends, first hop or redirect: the full URL is scope-checked (so a
// URL-prefix allow entry bounds the paths that may be requested), then the
// per-host HTTP rate limit is applied.
type limitedTransport struct {
	rt     http.RoundTripper
	dialer *Dialer
	ua     string
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.dialer.CheckURL(req.Context(), req.URL); err != nil {
		return nil, err
	}
	if t.dialer.Limits != nil {
		if err := t.dialer.Limits.WaitHTTP(req.Context(), req.URL.Hostname()); err != nil {
			return nil, err
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.ua)
	}
	return t.rt.RoundTrip(req)
}

// ReadBody reads at most max bytes of a response body and closes it.
func ReadBody(resp *http.Response, max int64) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// ParseAddrPort is a small helper used by netscan to build dial strings.
func ParseAddrPort(ip netip.Addr, port int) string {
	return net.JoinHostPort(ip.String(), fmt.Sprint(port))
}
