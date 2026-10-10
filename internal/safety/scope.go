// Package safety is the authorisation and harm-prevention layer: scope
// allow/deny, consent, ownership verification, rate limits, a scope-checked
// HTTP client and the redactor. Every network-touching code path uses it.
package safety

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/gerald/scnr/internal/domain"
)

// Error codes surfaced to users (exit 3 for gate refusals).
const (
	CodeAckRequired       = "E_ACK_REQUIRED"
	CodeScopeDenied       = "E_SCOPE_DENIED"
	CodeScopeNotAllowed   = "E_SCOPE_NOT_ALLOWED"
	CodeOwnershipRequired = "E_OWNERSHIP_REQUIRED"
	CodeCIDRTooLarge      = "E_CIDR_TOO_LARGE"
	CodeConsentDeclined   = "E_CONSENT_DECLINED"
	CodeUnresolvable      = "E_UNRESOLVABLE"
)

// RefusalError is returned when the gate or a dial-time check refuses.
type RefusalError struct {
	Code   string
	Target string
	Reason string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Target, e.Reason)
}

// IsRefusal reports whether err is a RefusalError.
func IsRefusal(err error) bool {
	var r *RefusalError
	return errors.As(err, &r)
}

// entryKind is the shape of one allow/deny entry.
type entryKind int

const (
	kindCIDR entryKind = iota
	kindIP
	kindHost
	kindWildcard
	kindURLPrefix
)

type entry struct {
	raw    string
	kind   entryKind
	prefix netip.Prefix
	addr   netip.Addr
	host   string // lowercased hostname / wildcard suffix
	// URL-prefix entries are compared component-wise, never by raw string
	// prefix, so "https://a.example" cannot admit "https://a.example.evil".
	scheme string
	port   string // "" = any port
	path   string // no trailing slash; "" = any path
}

func parseEntry(raw string) (entry, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return entry{}, errors.New("empty scope entry")
	}
	e := entry{raw: s}
	switch {
	case strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://"):
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return e, fmt.Errorf("bad URL scope entry %q", s)
		}
		if u.User != nil {
			return e, fmt.Errorf("URL scope entry %q must not carry credentials", s)
		}
		e.kind, e.host = kindURLPrefix, strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		e.scheme, e.port, e.path = strings.ToLower(u.Scheme), u.Port(), strings.TrimSuffix(u.Path, "/")
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return e, fmt.Errorf("bad CIDR scope entry %q", s)
		}
		e.kind, e.prefix = kindCIDR, p.Masked()
	case strings.HasPrefix(s, "*."):
		e.kind, e.host = kindWildcard, strings.ToLower(s[1:]) // ".example.com"
	default:
		if a, err := netip.ParseAddr(s); err == nil {
			e.kind, e.addr = kindIP, a.Unmap()
		} else {
			e.kind, e.host = kindHost, strings.ToLower(strings.TrimSuffix(s, "."))
		}
	}
	return e, nil
}

func (e entry) matches(host string, ip netip.Addr, rawURL string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch e.kind {
	case kindCIDR:
		return ip.IsValid() && e.prefix.Contains(ip.Unmap())
	case kindIP:
		return ip.IsValid() && e.addr == ip.Unmap()
	case kindHost:
		return host != "" && host == e.host
	case kindWildcard:
		return host != "" && strings.HasSuffix(host, e.host) && host != e.host[1:]
	case kindURLPrefix:
		if rawURL != "" {
			return e.matchesURL(rawURL)
		}
		// A URL prefix also admits its hostname for non-HTTP checks
		// (dial-time re-check, port scan of the URL's host).
		return host != "" && host == e.host
	}
	return false
}

// matchesURL compares a candidate URL to a URL-prefix entry component by
// component: same scheme, same host (case-insensitive), same port when the
// entry names one, and the entry path as a prefix on a segment boundary.
// Candidates carrying userinfo never match: "https://a.example@evil.net/"
// has host evil.net, and credentials in targets are not supported anyway.
func (e entry) matchesURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, e.scheme) {
		return false
	}
	if !strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), e.host) {
		return false
	}
	if e.port != "" && u.Port() != e.port {
		return false
	}
	if e.path == "" {
		return true
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return p == e.path || strings.HasPrefix(p, e.path+"/")
}

// containsPrefix reports whether entry fully covers the CIDR p.
func (e entry) containsPrefix(p netip.Prefix) bool {
	switch e.kind {
	case kindCIDR:
		return e.prefix.Bits() <= p.Bits() && e.prefix.Contains(p.Addr())
	case kindIP:
		return p.Bits() == p.Addr().BitLen() && e.addr == p.Addr()
	}
	return false
}

// overlapsPrefix reports whether entry shares any address with p.
func (e entry) overlapsPrefix(p netip.Prefix) bool {
	switch e.kind {
	case kindCIDR:
		return e.prefix.Overlaps(p)
	case kindIP:
		return p.Contains(e.addr)
	}
	return false
}

// BuiltinDeny lists addresses that are never legitimate scan targets:
// cloud instance-metadata and container-credential endpoints (AWS EC2 and
// ECS, Alibaba). They are link-local (so they would otherwise count as
// private) and are the classic SSRF/redirect target.
var BuiltinDeny = []string{"169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200"}

// Scope is the parsed allow/deny list. Deny always wins.
type Scope struct {
	allow []entry
	deny  []entry
	hash  string
}

// NewScope parses allow and deny entries. BuiltinDeny is always appended.
func NewScope(allow, deny []string) (*Scope, error) {
	s := &Scope{}
	for _, d := range BuiltinDeny {
		e, err := parseEntry(d)
		if err != nil {
			return nil, err
		}
		e.raw = d + " (built-in)"
		s.deny = append(s.deny, e)
	}
	for _, a := range allow {
		e, err := parseEntry(a)
		if err != nil {
			return nil, fmt.Errorf("scope.allow: %w", err)
		}
		s.allow = append(s.allow, e)
	}
	for _, d := range deny {
		e, err := parseEntry(d)
		if err != nil {
			return nil, fmt.Errorf("scope.deny: %w", err)
		}
		s.deny = append(s.deny, e)
	}
	al := append([]string(nil), allow...)
	dl := append([]string(nil), deny...)
	sort.Strings(al)
	sort.Strings(dl)
	s.hash = domain.SHA256Hex("allow:" + strings.Join(al, ",") + "\ndeny:" + strings.Join(dl, ","))
	return s, nil
}

// Hash is sha256 over the resolved allow/deny lists (stored on each scan).
func (s *Scope) Hash() string { return s.hash }

// Denied reports whether host or any ip matches a deny entry.
func (s *Scope) Denied(host string, ips []netip.Addr, rawURL string) (bool, string) {
	for _, d := range s.deny {
		if d.matches(host, netip.Addr{}, rawURL) {
			return true, d.raw
		}
		for _, ip := range ips {
			if d.matches(host, ip, rawURL) {
				return true, d.raw
			}
		}
	}
	return false, ""
}

// Allowed reports whether host or any ip matches an allow entry.
func (s *Scope) Allowed(host string, ips []netip.Addr, rawURL string) bool {
	for _, a := range s.allow {
		if a.matches(host, netip.Addr{}, rawURL) {
			return true
		}
		for _, ip := range ips {
			if a.matches(host, ip, rawURL) {
				return true
			}
		}
	}
	return false
}

// DenyAddresses returns the IP and CIDR deny entries (built-in ones
// included) in canonical form, for tools that take an exclusion list.
// Hostname and URL deny entries are enforced at dial time only.
func (s *Scope) DenyAddresses() []string {
	var out []string
	for _, d := range s.deny {
		switch d.kind {
		case kindCIDR:
			out = append(out, d.prefix.String())
		case kindIP:
			out = append(out, d.addr.String())
		}
	}
	return out
}

// PrefixDenied reports whether a deny entry fully covers the CIDR.
// Partial overlaps are enforced per host at dial time.
func (s *Scope) PrefixDenied(p netip.Prefix) (bool, string) {
	for _, d := range s.deny {
		if d.containsPrefix(p) {
			return true, d.raw
		}
	}
	return false, ""
}

// PrefixAllowed reports whether an allow entry fully covers the CIDR.
func (s *Scope) PrefixAllowed(p netip.Prefix) bool {
	for _, a := range s.allow {
		if a.containsPrefix(p) {
			return true
		}
	}
	return false
}

// PrefixOverlapsDeny reports whether any deny entry lies inside p.
func (s *Scope) PrefixOverlapsDeny(p netip.Prefix) bool {
	for _, d := range s.deny {
		if d.overlapsPrefix(p) {
			return true
		}
	}
	return false
}

// Check applies deny → private → allow to a host and its resolved
// addresses. It returns public=true when any address is non-private.
// Public targets must be explicitly allowed. Consent is the Gate's job.
func (s *Scope) Check(host string, ips []netip.Addr, rawURL string) (public bool, err error) {
	label := host
	if label == "" && len(ips) > 0 {
		label = ips[0].String()
	}
	if denied, by := s.Denied(host, ips, rawURL); denied {
		return false, &RefusalError{Code: CodeScopeDenied, Target: label, Reason: "matches deny entry " + by}
	}
	if len(ips) == 0 {
		return false, &RefusalError{Code: CodeUnresolvable, Target: label, Reason: "no addresses"}
	}
	for _, ip := range ips {
		if !IsPrivate(ip) {
			public = true
		}
	}
	if !public {
		return false, nil
	}
	if !s.Allowed(host, ips, rawURL) {
		return true, &RefusalError{Code: CodeScopeNotAllowed, Target: label, Reason: "public address not in scope.allow"}
	}
	return true, nil
}

// IsPrivate reports whether ip is loopback, RFC1918, link-local, CGNAT,
// ULA or unspecified. Anything else is treated as public.
func IsPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	if ip.Is4() && cgnat.Contains(ip) {
		return true
	}
	return false
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// AnyPrivate reports whether any address is private per IsPrivate.
func AnyPrivate(ips []netip.Addr) bool {
	for _, ip := range ips {
		if IsPrivate(ip) {
			return true
		}
	}
	return false
}

// ToNetIP converts for APIs that still want net.IP.
func ToNetIP(a netip.Addr) net.IP { return net.IP(a.AsSlice()) }

// FromNetIPs converts resolver results.
func FromNetIPs(addrs []net.IPAddr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, ip.Unmap())
		}
	}
	return out
}
