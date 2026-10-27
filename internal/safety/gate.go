package safety

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/iamstoick/scnr/internal/domain"
)

// Resolver is the subset of *net.Resolver the gate and dialer need, so tests
// can inject a fake.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ConsentFunc asks the user interactively. It must display plan and return
// true only if the user typed the target hostname/IP back. nil means
// non-interactive.
type ConsentFunc func(ctx context.Context, t domain.Target, plan string) (bool, error)

// VerifiedFunc reports whether host has a non-expired ownership verification.
type VerifiedFunc func(ctx context.Context, host string) (bool, error)

// CloudIdentityFunc confirms who the credentials are and returns the
// account/subscription/project id. It performs exactly one identity call
// (sts:GetCallerIdentity on AWS, one subscription read on Azure) and
// nothing else.
type CloudIdentityFunc func(ctx context.Context, t domain.Target) (CloudIdentity, error)

// CloudIdentity is the result of a cloud identity confirmation.
type CloudIdentity struct {
	Provider  string // "aws" | "azure"
	Account   string // 12-digit account id (AWS) or subscription UUID (Azure)
	Principal string // caller ARN (AWS) or service principal / managed identity (Azure)
	Source    string // "env" | "profile:<name>" | "web-identity" | "instance" | "managed-identity"
}

// Gate makes the per-target authorisation decision (Section 9).
type Gate struct {
	Scope        *Scope
	Acknowledged bool
	Resolver     Resolver
	Verified     VerifiedFunc
	Consent      ConsentFunc
	MaxHosts     int // explicit --max-hosts; 0 = not set
	// CloudIdentity confirms the account behind a cloud target before any
	// other API call; nil means cloud targets are refused.
	CloudIdentity CloudIdentityFunc
	// CloudAccounts is cloud.aws.accounts from the scope file: a confirmed
	// account listed here is allowed without a prompt.
	CloudAccounts []string
	// CloudIdentityAzure and CloudAccountsAzure are the Azure equivalents
	// (subscription UUIDs in cloud.azure.subscriptions); nil means
	// azure:// targets are refused.
	CloudIdentityAzure CloudIdentityFunc
	CloudAccountsAzure []string
}

// CIDR caps (Section 9 step 6).
const (
	MaxPrivateCIDRHosts = 1 << 16 // /16
	MaxPublicCIDRHosts  = 1 << 8  // /24
	MaxIPv6PrefixHosts  = 1 << 8  // /120
)

// Decision is a positive gate result.
type Decision struct {
	Target           domain.Target
	Public           bool
	ConsentMethod    string
	Addrs            []netip.Addr
	HostCount        int
	MaxHostsOverride bool // user raised the CIDR cap; audited by caller
	// Identity is set for cloud targets: the confirmed account the scan is
	// bound to. Target.Value is rewritten to "<provider>://<account>".
	Identity *CloudIdentity
}

// Decide applies the ordered rules. plan is shown to the user before
// interactive consent for public targets.
func (g *Gate) Decide(ctx context.Context, t domain.Target, plan string) (*Decision, error) {
	if !g.Acknowledged {
		return nil, &RefusalError{Code: CodeAckRequired, Target: t.Raw,
			Reason: "authorization not acknowledged; run `scnr scope init` or pass --ack-authorized"}
	}
	d := &Decision{Target: t, HostCount: 1}
	switch t.Type {
	case domain.TargetCloud:
		return g.decideCloud(ctx, d, plan)
	case domain.TargetPath, domain.TargetImage:
		d.ConsentMethod = domain.ConsentLocal
		return d, nil
	case domain.TargetCIDR:
		return g.decideCIDR(ctx, d)
	}
	return g.decideHost(ctx, d, plan)
}

func (g *Gate) decideHost(ctx context.Context, d *Decision, plan string) (*Decision, error) {
	t := d.Target
	host := t.Hostname
	if host == "" {
		host = t.Value
	}
	rawURL := ""
	if t.Type == domain.TargetURL {
		rawURL = t.Value
	}
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return nil, &RefusalError{Code: CodeUnresolvable, Target: t.Raw, Reason: err.Error()}
	}
	d.Addrs = addrs
	public, err := g.Scope.Check(host, addrs, rawURL)
	if err != nil {
		return nil, err
	}
	d.Public = public
	if !public {
		d.ConsentMethod = domain.ConsentPrivateRange
		return d, nil
	}
	// Public: allow-listed (checked above) AND verified or interactive consent.
	if g.Verified != nil {
		ok, err := g.Verified(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("verification lookup: %w", err)
		}
		if ok {
			d.ConsentMethod = domain.ConsentDNSTXT
			return d, nil
		}
	}
	hint := fmt.Sprintf("run `scnr verify %s` or scan interactively", host)
	if _, err := netip.ParseAddr(host); err == nil {
		hint = "bare public IPs can only be verified via the well-known file (`scnr verify " + host + " --check`) or scanned interactively"
	}
	return g.askConsent(ctx, d, plan, "public target requires ownership verification: "+hint)
}

// askConsent is the interactive fallback for public targets. nonInteractive
// is the refusal reason when no consent function is available.
func (g *Gate) askConsent(ctx context.Context, d *Decision, plan, nonInteractive string) (*Decision, error) {
	if g.Consent == nil {
		code := CodeOwnershipRequired
		if d.Identity != nil {
			code = CodeCloudAccountNotAllowed
		}
		return nil, &RefusalError{Code: code, Target: d.Target.Raw, Reason: nonInteractive}
	}
	ok, err := g.Consent(ctx, d.Target, plan)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &RefusalError{Code: CodeConsentDeclined, Target: d.Target.Raw, Reason: "consent not given"}
	}
	d.ConsentMethod = domain.ConsentInteractive
	return d, nil
}

// decideCloud binds the scan to the account the credentials actually
// belong to: one identity call, then the allowlist, then (interactively)
// the user typing the account id back. The decision's Target is rewritten
// to the confirmed account so the asset key, reports and every later API
// client refer to it, and the profile moves to Labels["profile"]. Azure
// works the same way with subscription UUIDs.
func (g *Gate) decideCloud(ctx context.Context, d *Decision, plan string) (*Decision, error) {
	t := d.Target
	az := strings.HasPrefix(t.Value, "azure://")
	identity, allow, acctRe, noun, scopeKey := g.CloudIdentity, g.CloudAccounts, cloudAccountRe, "account", "accounts"
	if az {
		identity, allow, acctRe, noun, scopeKey = g.CloudIdentityAzure, g.CloudAccountsAzure, azureSubscriptionRe, "subscription", "subscriptions"
	}
	if identity == nil {
		return nil, &RefusalError{Code: CodeCloudIdentity, Target: t.Raw, Reason: "no cloud identity confirmation available"}
	}
	id, err := identity(ctx, t)
	if err != nil {
		if IsRefusal(err) {
			return nil, err
		}
		return nil, &RefusalError{Code: CodeCloudIdentity, Target: t.Raw, Reason: "could not confirm the account behind these credentials: " + err.Error()}
	}
	if id.Provider == "" || !acctRe.MatchString(id.Account) {
		return nil, &RefusalError{Code: CodeCloudIdentity, Target: t.Raw, Reason: "identity call returned no usable account id"}
	}
	d.Identity = &id
	profile := strings.TrimPrefix(t.Value, id.Provider+"://")
	t.Value = id.Provider + "://" + id.Account
	if profile != "" {
		if t.Labels == nil {
			t.Labels = map[string]string{}
		}
		t.Labels["profile"] = profile
	}
	// consentPrompt echoes Hostname when set; the account id is what the
	// user must type back.
	t.Hostname = id.Account
	d.Target = t
	for _, a := range allow {
		if a == id.Account {
			d.ConsentMethod = domain.ConsentCloudAllowlist
			return d, nil
		}
	}
	plan = fmt.Sprintf("You are about to scan %s %s %s as %s (credentials from %s).\n%s", strings.ToUpper(id.Provider), noun, id.Account, id.Principal, id.Source, plan)
	return g.askConsent(ctx, d, plan, fmt.Sprintf("%s %s is not in cloud.%s.%s; add it to the scope file or confirm interactively", noun, id.Account, id.Provider, scopeKey))
}

var cloudAccountRe = regexp.MustCompile(`^[0-9]{12}$`)

// azureSubscriptionRe matches a subscription UUID, any case.
var azureSubscriptionRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (g *Gate) decideCIDR(ctx context.Context, d *Decision) (*Decision, error) {
	t := d.Target
	p, err := netip.ParsePrefix(t.Value)
	if err != nil {
		return nil, &RefusalError{Code: CodeUnresolvable, Target: t.Raw, Reason: "bad CIDR"}
	}
	p = p.Masked()
	count := prefixHostCount(p)
	d.HostCount = count
	if denied, by := g.Scope.PrefixDenied(p); denied {
		return nil, &RefusalError{Code: CodeScopeDenied, Target: t.Raw, Reason: "matches deny entry " + by}
	}
	// Private only if the whole range is private: check both ends.
	public := !IsPrivate(p.Addr()) || !IsPrivate(lastAddr(p))
	d.Public = public
	cap := MaxPrivateCIDRHosts
	if public {
		cap = MaxPublicCIDRHosts
	}
	if p.Addr().Is6() && cap > MaxIPv6PrefixHosts {
		cap = MaxIPv6PrefixHosts
	}
	if count > cap {
		if g.MaxHosts < count {
			return nil, &RefusalError{Code: CodeCIDRTooLarge, Target: t.Raw,
				Reason: fmt.Sprintf("%d hosts exceeds cap of %d; pass --max-hosts %d to override (audited)", count, cap, count)}
		}
		d.MaxHostsOverride = true
	}
	if !public {
		d.ConsentMethod = domain.ConsentPrivateRange
		return d, nil
	}
	if !g.Scope.PrefixAllowed(p) {
		return nil, &RefusalError{Code: CodeScopeNotAllowed, Target: t.Raw, Reason: "public range not fully covered by scope.allow"}
	}
	// A public range has no single hostname to verify; interactive only.
	return g.askConsent(ctx, d, fmt.Sprintf("%d hosts in %s", count, p),
		"public ranges require interactive consent (no ownership verification path for ranges)")
}

func (g *Gate) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return ResolveAll(ctx, g.Resolver, host)
}

// ResolveAll returns every address for host (an IP literal resolves to itself).
func ResolveAll(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(host, ".")
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := FromNetIPs(addrs)
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s: no addresses", host)
	}
	return ips, nil
}

func prefixHostCount(p netip.Prefix) int {
	bits := p.Addr().BitLen() - p.Bits()
	if bits >= 31 {
		return int(^uint(0) >> 1) // effectively unbounded; will be refused
	}
	return 1 << bits
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	n := new(big.Int).SetBytes(a.AsSlice())
	host := a.BitLen() - p.Bits()
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(host)), big.NewInt(1))
	n.Or(n, mask)
	b := n.FillBytes(make([]byte, a.BitLen()/8))
	out, _ := netip.AddrFromSlice(b)
	return out
}

// Hosts enumerates the usable addresses of a CIDR (for /31,/32 and IPv6 all
// addresses; otherwise network and broadcast are skipped).
func Hosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	count := prefixHostCount(p)
	out := make([]netip.Addr, 0, count)
	a := p.Addr()
	for i := 0; i < count && p.Contains(a); i++ {
		out = append(out, a)
		a = a.Next()
	}
	if p.Addr().Is4() && count > 2 {
		return out[1 : len(out)-1]
	}
	return out
}

// URLHost extracts the hostname from a URL target value.
func URLHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
