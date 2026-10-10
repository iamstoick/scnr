package safety

import (
	"fmt"
	"net/http"
	"strings"
)

// NewEndpointClient returns a client for a fixed, declared set of non-target
// hosts (osv.dev, feed hosts, the OSV bundle bucket). It is the same
// scope-checked client as NewHTTPClient with the host allowlist standing in
// for the scan scope: every request and every redirect hop must name one of
// hosts (private addresses included, so a redirect into the operator's LAN
// is refused), the built-in deny list (cloud metadata endpoints) still
// applies, and no proxy is used. Hosts are hostnames or IP literals; the
// list is fixed at construction and cannot grow from a response.
func NewEndpointClient(hosts []string, o HTTPOptions) (*http.Client, error) {
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
	scope, err := NewScope(allow, nil)
	if err != nil {
		return nil, fmt.Errorf("endpoint client: %w", err)
	}
	d := &Dialer{Scope: scope, RequireAllow: true}
	return NewHTTPClient(d, o), nil
}
