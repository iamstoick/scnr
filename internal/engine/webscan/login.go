package webscan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// maxLoginBodyBytes caps a login form body: credentials plus a few small
// extra fields must never approach a payload size.
const maxLoginBodyBytes = 4096

// loginSession performs the single configured form login (if any) and
// returns the client the rest of the scan should use, plus the session
// cookie names for the prober's invalidation watch. Any failure emits a
// web.login-failed finding and falls back to the unauthenticated client:
// a failed login reduces coverage, it never aborts the scan. Credentials
// are posted only to the login URL's own origin, once, never retried.
func (e *Engine) loginSession(ctx context.Context, o engine.Options, base *url.URL, assetKey string, red *safety.Redactor, emit engine.EmitFunc) (*http.Client, []string) {
	client := o.HTTP
	if o.Auth == nil || !o.Auth.HasLogin() {
		return client, nil
	}
	targetOrigin := safety.OriginHostPort(base)
	fail := func(reason string) (*http.Client, []string) {
		f := e.rules.NewFinding("web.login-failed", assetKey, base.String(), domain.Confirmed)
		f.Evidence = []domain.Evidence{red.TextEvidence("response", base.String(), reason)}
		_ = emit(f)
		return client, nil
	}
	spec, ok := o.Auth.LoginFor(targetOrigin)
	if !ok {
		return fail("login not authorised for this origin; credentials never sent")
	}
	if spec.Origin != targetOrigin {
		return fail("login URL origin does not match the target origin; credentials never sent")
	}
	form := url.Values{spec.UserField: {spec.User}, spec.PassField: {spec.Pass}}
	for k, v := range spec.Extra {
		form[k] = []string{v}
	}
	body := form.Encode()
	if len(body) > maxLoginBodyBytes {
		return fail("login form exceeds size cap; nothing sent")
	}
	rctx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, spec.URL, strings.NewReader(body))
	if err != nil {
		return fail("login request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		if _, rok := safety.AsRedirectOutOfScope(err); rok {
			return fail("login redirected outside the authorised scope; session not established")
		}
		if safety.IsRefusal(err) {
			return fail("login refused by the safety gate; session not established")
		}
		return fail("login request failed; session not established")
	}
	respBody, err := safety.ReadBody(resp, maxBodyBytes)
	if err != nil && len(respBody) == 0 {
		return fail("login response could not be read; session not established")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 399 || !strings.Contains(string(respBody), spec.Success) {
		return fail(fmt.Sprintf("login response did not show the success marker (HTTP %d); continuing unauthenticated", resp.StatusCode))
	}
	var cookies []*http.Cookie
	var names []string
	for _, c := range resp.Cookies() {
		if c == nil || c.Name == "" {
			continue
		}
		cookies = append(cookies, &http.Cookie{Name: c.Name, Value: c.Value})
		names = append(names, c.Name)
	}
	if len(cookies) == 0 {
		return fail("login looked successful but set no session cookie; continuing unauthenticated")
	}
	if o.HTTP.Transport == nil {
		return fail("no transport for a session client; continuing unauthenticated")
	}
	sess := safety.NewSessionClient(o.HTTP, targetOrigin, cookies)
	f := e.rules.NewFinding("web.login-success", assetKey, base.String(), domain.Confirmed)
	f.Title = fmt.Sprintf("Logged in as %q", spec.User)
	f.Evidence = []domain.Evidence{red.TextEvidence("response", spec.URL, "session cookies: "+strings.Join(names, ", "))}
	if err := emit(f); err != nil {
		return client, nil
	}
	return sess, names
}

// sessionNames appends dynamic session cookie names to the static ones
// for the prober's session-invalidation watch.
func sessionNames(o engine.Options, dynamic []string) []string {
	var out []string
	if o.Auth != nil {
		out = append(out, o.Auth.CookieNames()...)
	}
	return append(out, dynamic...)
}
