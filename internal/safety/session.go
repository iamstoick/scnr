package safety

import (
	"net/http"
)

// sessionTransport adds session cookies from a completed login to requests
// for exactly one origin, on top of a scope-checked transport. Static auth
// material keeps flowing through the base client as before.
type sessionTransport struct {
	base    http.RoundTripper
	origin  string
	cookies []*http.Cookie
}

func (t *sessionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req != nil && req.URL != nil && OriginHostPort(req.URL) == t.origin {
		for _, c := range t.cookies {
			req.AddCookie(c)
		}
	}
	return t.base.RoundTrip(req)
}

// NewSessionClient returns a copy of base that also sends cookies (from a
// completed form login) to requests for origin, and only there. Timeout,
// redirect policy and jar are inherited; the transport stays the
// scope-checked one, so every request keeps the same safety properties.
func NewSessionClient(base *http.Client, origin string, cookies []*http.Cookie) *http.Client {
	if base == nil {
		return nil
	}
	var cs []*http.Cookie
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		cs = append(cs, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	out := *base
	out.Transport = &sessionTransport{base: base.Transport, origin: origin, cookies: cs}
	return &out
}
