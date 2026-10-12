package safety

import (
	"fmt"
	"net/http"
	"strings"
)

// EndpointPolicy tunes NewEndpointClientPolicy for one client class.
type EndpointPolicy struct {
	// RefusePrivate makes every destination resolve to public address space
	// (E_ENDPOINT_PRIVATE otherwise). Cloud API clients set it: a vendor
	// endpoint that resolves into RFC1918/loopback is a PrivateLink/VPC
	// endpoint or a DNS trick, and neither is supported in this version.
	RefusePrivate bool
	// AllowMetadata drops the built-in metadata deny entries for this one
	// client. It exists for instance-credential lookups only
	// (cloud.aws.instance_credentials: true) and the caller audits it.
	AllowMetadata bool
	// RefuseRedirects makes the client never follow redirects: the
	// caller sees the 3xx response (ErrUseLastResponse) instead. Set
	// for the daemon notify client, which must not be steered.
	RefuseRedirects bool
}

// NewEndpointClient returns a client for a fixed, declared set of non-target
// hosts (osv.dev, feed hosts, the OSV bundle bucket). It is the same
// scope-checked client as NewHTTPClient with the host allowlist standing in
// for the scan scope: every request and every redirect hop must name one of
// hosts (private addresses included, so a redirect into the operator's LAN
// is refused), the built-in deny list (cloud metadata endpoints) still
// applies, and no proxy is used. Hosts are hostnames, wildcard suffixes
// ("*.amazonaws.com") or IP literals; the list is fixed at construction and
// cannot grow from a response.
func NewEndpointClient(hosts []string, o HTTPOptions) (*http.Client, error) {
	return NewEndpointClientPolicy(hosts, o, EndpointPolicy{})
}

// NewEndpointClientPolicy is NewEndpointClient with an explicit policy.
func NewEndpointClientPolicy(hosts []string, o HTTPOptions, p EndpointPolicy) (*http.Client, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("endpoint client: no hosts")
	}
	allow := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.ContainsAny(h, "/ \t") {
			return nil, fmt.Errorf("endpoint client: bad host %q", h)
		}
		allow = append(allow, h)
	}
	scope, err := newScope(allow, nil, nil, !p.AllowMetadata)
	if err != nil {
		return nil, fmt.Errorf("endpoint client: %w", err)
	}
	d := &Dialer{Scope: scope, RequireAllow: true, RefusePrivate: p.RefusePrivate, RefuseRedirects: p.RefuseRedirects}
	return NewHTTPClient(d, o), nil
}
