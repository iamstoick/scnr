// Package webscan is the native web engine: passive checks on a handful of
// fixed responses plus a safe-matcher-only YAML template engine. Every
// request goes through the scope-checked HTTP client in engine.Options;
// there is no other network path in this package.
package webscan

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
)

//go:embed rules/*.yaml templates/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "webscan"

const (
	maxBodyBytes      = 1 << 20
	snippetBytes      = 256
	requestParallel   = 4
	perRequestTimeout = 15 * time.Second
	canaryOrigin      = "https://scnr-canary.invalid"
)

var versionRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

var mixedContentRe = regexp.MustCompile(`(?i)\b(?:src|href)\s*=\s*["']http://[^"']+["']`)

// Engine implements engine.Engine.
type Engine struct {
	rules    engine.RuleSet
	embedded []*Template
}

// New loads embedded rules and templates.
func New() (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	tpls, err := LoadFS(assets, "templates")
	if err != nil {
		return nil, fmt.Errorf("embedded templates: %w", err)
	}
	return &Engine{rules: rs, embedded: tpls}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Supports URL targets only; netscan labels HTTP services on hosts.
func (e *Engine) Supports(t domain.Target) bool { return t.Type == domain.TargetURL }

// Templates returns the embedded set merged with the user directory (if
// any). Intrusive templates are excluded: --allow-intrusive does not exist
// in this phase, so only safe templates ever run.
func (e *Engine) Templates(userDir string) ([]*Template, error) {
	var user []*Template
	if userDir != "" {
		var errs []error
		user, errs = LoadDir(userDir)
		if len(errs) > 0 {
			return nil, fmt.Errorf("--templates %s: %w", userDir, errors.Join(errs...))
		}
	}
	all, err := Merge(e.embedded, user)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, t := range all {
		if t.Safety == domain.SafetySafe {
			out = append(out, t)
		}
	}
	return out, nil
}

// EmbeddedCount is used by tests and `templates list`.
func (e *Engine) EmbeddedCount() int { return len(e.embedded) }

// TemplateSetInfo returns how many templates will run for userDir and a
// content hash over them (see HashTemplates), for the scan audit row.
func (e *Engine) TemplateSetInfo(userDir string) (int, string, error) {
	tpls, err := e.Templates(userDir)
	if err != nil {
		return 0, "", err
	}
	return len(tpls), HashTemplates(tpls), nil
}

func countRequests(tpls []*Template) int {
	n := 0
	for _, t := range tpls {
		for _, s := range t.HTTP {
			n += len(s.Path)
		}
	}
	return n
}

// Plan implements engine.Engine.
func (e *Engine) Plan(_ context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	tpls, err := e.Templates(o.TemplatesDir)
	if err != nil {
		return engine.Plan{}, err
	}
	n := 1 + countRequests(tpls)
	rps := 10
	if o.Limiter != nil && o.Limiter.HTTPRPSPerHost > 0 {
		rps = o.Limiter.HTTPRPSPerHost
	}
	return engine.Plan{
		Summary:     fmt.Sprintf("passive header/cookie checks on GET / plus %d safe templates (%d requests) at <= %d req/s", len(tpls), n, rps),
		EstRequests: n,
		EstDuration: time.Duration(n/rps+1) * time.Second,
		Network:     true,
	}, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	if o.HTTP == nil {
		return errors.New("webscan requires the scope-checked HTTP client")
	}
	base, err := url.Parse(t.Value)
	if err != nil || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return fmt.Errorf("webscan: invalid target URL")
	}
	tpls, err := e.Templates(o.TemplatesDir)
	if err != nil {
		return err
	}
	red := o.Redactor
	if red == nil {
		red = safety.NewRedactor()
	}
	assetKey := t.AssetKey()
	var emitMu sync.Mutex
	safeEmit := func(f domain.Finding) error {
		emitMu.Lock()
		defer emitMu.Unlock()
		return emit(f)
	}
	redirects := &redirectTracker{seen: map[string]bool{}}

	// Passive checks on the target itself.
	resp, err := e.fetch(ctx, o.HTTP, http.MethodGet, t.Value, map[string]string{"Origin": canaryOrigin})
	if err != nil {
		if r, ok := safety.AsRedirectOutOfScope(err); ok {
			if err := redirects.emit(e, r, assetKey, red, safeEmit); err != nil {
				return err
			}
		} else if safety.IsRefusal(err) {
			return err
		} else {
			return fmt.Errorf("GET %s: %w", t.Value, redactedErr(red, err))
		}
	} else if err := e.passive(base, resp, assetKey, red, safeEmit); err != nil {
		return err
	}

	// Templates: bounded parallelism; the client enforces per-host rps.
	// Paths outside a URL-prefix allow entry are never requested: the
	// transport would refuse them anyway, but a refusal there aborts the
	// engine, so they are filtered and counted here instead.
	origin := &url.URL{Scheme: base.Scheme, Host: base.Host}
	inScope := urlScopeFilter(base, o)
	sem := semaphore.NewWeighted(requestParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	setErr := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	outOfScope := 0
	for _, tpl := range tpls {
		for si := range tpl.HTTP {
			step := &tpl.HTTP[si]
			for _, p := range step.Path {
				target := stepURL(origin, p)
				if !inScope(target) {
					outOfScope++
					continue
				}
				if err := sem.Acquire(ctx, 1); err != nil {
					wg.Wait()
					return err
				}
				wg.Add(1)
				go func(tpl *Template, step *Step, p, target string) {
					defer wg.Done()
					defer sem.Release(1)
					if err := e.runStep(ctx, o.HTTP, tpl, step, p, target, assetKey, red, redirects, safeEmit); err != nil {
						setErr(err)
					}
				}(tpl, step, p, target)
			}
		}
	}
	wg.Wait()
	if outOfScope > 0 && o.Log != nil {
		o.Log.Info("webscan: template requests outside the allowed URL prefix were not sent", "target", t.Value, "skipped", outOfScope)
	}
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// stepURL joins a validated template path onto the target origin.
func stepURL(origin *url.URL, p string) string {
	u := *origin
	u.Path = p
	return u.String()
}

// urlScopeFilter returns a predicate reporting whether a request URL on the
// target's origin is admitted by the scope. The target host's gate-pinned
// addresses (or the IP literal) stand in for resolution; when neither is
// available the predicate admits everything and the transport decides.
func urlScopeFilter(base *url.URL, o engine.Options) func(rawURL string) bool {
	if o.Scope == nil {
		return func(string) bool { return true }
	}
	host := base.Hostname()
	var ips []netip.Addr
	if o.Dialer != nil {
		ips = o.Dialer.Pinned(host)
	}
	if len(ips) == 0 {
		if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			ips = []netip.Addr{ip}
		}
	}
	if len(ips) == 0 {
		return func(string) bool { return true }
	}
	return func(rawURL string) bool {
		_, err := o.Scope.Check(host, ips, rawURL)
		return err == nil
	}
}

// fetch performs one request and reads a capped body.
func (e *Engine) fetch(ctx context.Context, client *http.Client, method, rawURL string, headers map[string]string) (*Response, error) {
	rctx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := safety.ReadBody(resp, maxBodyBytes)
	if err != nil && len(body) == 0 {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

func (e *Engine) runStep(ctx context.Context, client *http.Client, tpl *Template, step *Step, p, target, assetKey string, red *safety.Redactor, redirects *redirectTracker, emit engine.EmitFunc) error {
	resp, err := e.fetch(ctx, client, step.Method, target, step.Headers)
	if err != nil {
		if r, ok := safety.AsRedirectOutOfScope(err); ok {
			return redirects.emit(e, r, assetKey, red, emit)
		}
		if safety.IsRefusal(err) {
			return err
		}
		return nil // connection-level failure: template does not match
	}
	if !step.Matches(resp) {
		return nil
	}
	f := domain.Finding{AssetKey: assetKey, Location: target, Confidence: domain.Firm, Status: domain.StatusOpen}
	tpl.Rule().Apply(&f)
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, target)
	summary := fmt.Sprintf("%s %s -> HTTP %d, %d bytes", step.Method, p, resp.Status, len(resp.Body))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		summary += ", " + ct
	}
	// Bodies of high/critical matches (exposed configs, dumps, keys) are
	// never quoted; only the fact of the match and extracted values.
	if f.Severity <= domain.Medium && len(resp.Body) > 0 {
		snippet := resp.Body
		if len(snippet) > snippetBytes {
			snippet = snippet[:snippetBytes]
		}
		summary += "\n" + string(snippet)
	}
	f.Evidence = []domain.Evidence{red.TextEvidence("response", target, summary)}
	for i := range step.Extractors {
		for _, v := range step.Extractors[i].Extract(resp) {
			if len(f.Evidence) >= domain.MaxEvidencePerFinding {
				break
			}
			f.Evidence = append(f.Evidence, red.TextEvidence("response", target, "extracted: "+v))
		}
	}
	return emit(f)
}

// passive runs the header/cookie/version/CORS/mixed-content checks on the
// response of GET <target>.
func (e *Engine) passive(base *url.URL, r *Response, assetKey string, red *safety.Redactor, emit engine.EmitFunc) error {
	loc := base.String()
	https := base.Scheme == "https"
	headerEv := func(names ...string) []domain.Evidence {
		var lines []string
		for _, n := range names {
			for _, v := range r.Header.Values(n) {
				lines = append(lines, n+": "+v)
			}
		}
		if len(lines) == 0 {
			lines = []string{fmt.Sprintf("HTTP %d; header(s) %s absent", r.Status, strings.Join(names, ", "))}
		}
		return []domain.Evidence{red.TextEvidence("response", loc, strings.Join(lines, "\n"))}
	}
	mk := func(id string, ev []domain.Evidence) error {
		f := e.rules.NewFinding(id, assetKey, loc, domain.Confirmed)
		f.Evidence = ev
		return emit(f)
	}
	isHTML := strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html")

	if isHTML || r.Header.Get("Content-Type") == "" {
		csp := r.Header.Get("Content-Security-Policy")
		if csp == "" {
			if err := mk("web.header.csp-missing", headerEv("Content-Security-Policy")); err != nil {
				return err
			}
		}
		if r.Header.Get("X-Content-Type-Options") == "" {
			if err := mk("web.header.xcto-missing", headerEv("X-Content-Type-Options")); err != nil {
				return err
			}
		}
		if r.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			if err := mk("web.header.frame-protection-missing", headerEv("X-Frame-Options", "Content-Security-Policy")); err != nil {
				return err
			}
		}
	}
	if https && r.Header.Get("Strict-Transport-Security") == "" {
		if err := mk("web.header.hsts-missing", headerEv("Strict-Transport-Security")); err != nil {
			return err
		}
	}
	for _, c := range r.Header.Values("Set-Cookie") {
		name, flags := parseCookie(c)
		if name == "" {
			continue
		}
		var missing []string
		if https && !flags["secure"] {
			missing = append(missing, "Secure")
		}
		if !flags["httponly"] {
			missing = append(missing, "HttpOnly")
		}
		if !flags["samesite"] {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		f := e.rules.NewFinding("web.cookie.insecure-flags", assetKey, loc+"#cookie:"+name, domain.Confirmed)
		f.Title = fmt.Sprintf("Cookie %q is missing %s", name, strings.Join(missing, ", "))
		f.Evidence = []domain.Evidence{red.TextEvidence("response", loc, "Set-Cookie: "+name+"=<redacted>; "+attrsOnly(c))}
		if err := emit(f); err != nil {
			return err
		}
	}
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if v := r.Header.Get(h); v != "" && versionRe.MatchString(v) {
			f := e.rules.NewFinding("web.server-version-disclosure", assetKey, loc+"#"+strings.ToLower(h), domain.Confirmed)
			f.Title = fmt.Sprintf("Software version disclosed in %s header", h)
			f.Evidence = headerEv(h)
			if err := emit(f); err != nil {
				return err
			}
		}
	}
	acao := r.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(r.Header.Get("Access-Control-Allow-Credentials"), "true")
	if acac && (acao == "*" || strings.EqualFold(acao, canaryOrigin)) {
		if err := mk("web.cors.credentials-any-origin", headerEv("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials")); err != nil {
			return err
		}
	}
	if https && isHTML {
		if m := mixedContentRe.Find(r.Body); m != nil {
			if err := mk("web.mixed-content", []domain.Evidence{red.TextEvidence("response", loc, string(m))}); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseCookie returns the cookie name and the lowercase attribute set.
func parseCookie(s string) (string, map[string]bool) {
	parts := strings.Split(s, ";")
	nv := strings.TrimSpace(parts[0])
	name := nv
	if i := strings.IndexByte(nv, '='); i >= 0 {
		name = nv[:i]
	}
	flags := map[string]bool{}
	for _, p := range parts[1:] {
		p = strings.ToLower(strings.TrimSpace(p))
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = p[:i]
		}
		flags[p] = true
	}
	return name, flags
}

func attrsOnly(c string) string {
	parts := strings.Split(c, ";")
	if len(parts) < 2 {
		return ""
	}
	out := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		out = append(out, strings.TrimSpace(p))
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

func redactedErr(red *safety.Redactor, err error) error {
	return errors.New(red.Redact(err.Error()))
}

// redirectTracker emits web.redirect-out-of-scope once per destination.
type redirectTracker struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (rt *redirectTracker) emit(e *Engine, r *safety.RedirectOutOfScopeError, assetKey string, red *safety.Redactor, emit engine.EmitFunc) error {
	rt.mu.Lock()
	dup := rt.seen[r.To]
	rt.seen[r.To] = true
	rt.mu.Unlock()
	if dup {
		return nil
	}
	f := e.rules.NewFinding("web.redirect-out-of-scope", assetKey, r.From, domain.Confirmed)
	f.Evidence = []domain.Evidence{red.TextEvidence("response", r.From, "Location: "+r.To+" (not followed)")}
	return emit(f)
}
