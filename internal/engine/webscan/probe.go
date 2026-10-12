package webscan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// AllowedPayloadRe is the entire active-payload alphabet: the fixed "scnr"
// prefix, 12 hex chars of randomness, and at most one quote pair plus a
// bare <. The only outbound probe value outside this alphabet is the fixed
// canary origin used for open-redirect detection (an .invalid host that is
// placed, never followed). TestPayloadAlphabet enforces both halves.
var AllowedPayloadRe = regexp.MustCompile(`^scnr[0-9a-f]{12}(?:'"<)?$`)

// probeSuffix is the most our probes ever append to a marker: a single
// quote, a double quote and a bare angle bracket. No statement, no tag,
// no event handler — ever.
const probeSuffix = `'"<`

// probeBodyBytes caps probe response bodies at 256 KiB.
const probeBodyBytes = 256 << 10

// probeEvidenceWindow is the body excerpt around a match (≤ 256 bytes).
const probeEvidenceWindow = 256

// canaryHost is the .invalid host placed in redirect-shaped parameters.
const canaryHost = "scnr-canary.invalid"

// redirectParamRe names the parameters worth an open-redirect probe.
var redirectParamRe = regexp.MustCompile(`(?i)^(url|next|redirect|return|returnurl|return_to|goto|dest|destination|continue|target|redir|r|u|back|callback)$`)

// errorSignatures is the fixed RE2 set of database/framework error
// markers. A single quote in a GET parameter is the entire "injection";
// these only recognise the server's own error text.
var errorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`SQLSTATE`),
	regexp.MustCompile(`ORA-\d{5}`),
	regexp.MustCompile(`You have an error in your SQL syntax`),
	regexp.MustCompile(`pg_query\(`),
	regexp.MustCompile(`Unclosed quotation mark`),
	regexp.MustCompile(`Traceback \(most recent call last\)`),
	regexp.MustCompile(`at java\.`),
	regexp.MustCompile(`Warning: .* on line \d+`),
}

// entityRe spots HTML-encoded quotes near a reflected marker.
var entityRe = regexp.MustCompile(`&(?:#0*39|#0*34|#0*60|#0*62|#x27|#x22|#x3c|#x3e|quot|apos|lt|gt);`)

// makeMarker returns one "scnr" + 12 hex chars marker.
func makeMarker() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("marker randomness: %w", err)
	}
	return "scnr" + hex.EncodeToString(b[:]), nil
}

// probePayload appends the inert quote suffix to a marker.
func probePayload(marker string) string { return marker + probeSuffix }

// Prober sends inert-marker probes at crawled page parameters: one
// reflection/error request per parameter plus an open-redirect request for
// redirect-shaped parameters. Probing is sequential so the budget is
// exact; the transport's per-host rate limit paces requests anyway.
type Prober struct {
	Client *http.Client
	Budget int
	Rules  engine.RuleSet
	Red    *safety.Redactor
	// AssetKey tags every emitted finding; set by the engine.
	AssetKey string
	// SessionCookies names the authenticated session cookies (names only).
	// When the server clears one, probing stops instead of continuing
	// anonymously.
	SessionCookies []string
	// OnProbeValue records (param, value) pairs the prober sets (tests).
	// Discovered parameter values echoed back untouched are not prober
	// payloads and are not recorded: the alphabet invariant governs what
	// the prober generates.
	OnProbeValue func(param, value string)
}

// ProbeStats accounts the probe phase. Truncated means the budget ran out
// (the engine emits web.probe-truncated and a PartialError).
// SessionInvalidated means the server cleared the session cookie (the
// prober already emitted web.session-invalidated).
type ProbeStats struct {
	Requests           int
	Truncated          bool
	SessionInvalidated bool
}

// Probe runs the probe phase over crawled pages.
func (p *Prober) Probe(ctx context.Context, pages []Page, emit engine.EmitFunc) (ProbeStats, error) {
	var st ProbeStats
	red := p.Red
	if red == nil {
		red = safety.NewRedactor()
	}
	for _, page := range pages {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		if LooksDestructive(page.URL, "") {
			continue // seeds included: never probe state-changing URLs
		}
		base, err := url.Parse(page.URL)
		if err != nil {
			continue
		}
		loc := func(param string) string {
			return stableLocation(base, param)
		}
		for _, param := range page.Params {
			if st.Requests >= p.Budget {
				st.Truncated = true
				return st, nil
			}
			marker, err := makeMarker()
			if err != nil {
				continue
			}
			payload := probePayload(marker)
			probed := cloneWithParam(base, param, payload)
			if p.OnProbeValue != nil {
				p.OnProbeValue(param, payload)
			}
			resp, perr := p.get(ctx, probed)
			st.Requests++
			if perr != nil {
				continue // dead end: refused, reset, timeout
			}
			if isSessionClearedResp(resp, p.SessionCookies) {
				_ = resp.Body.Close()
				st.SessionInvalidated = true
				return st, p.emitSessionInvalidated(emit, red, loc(""))
			}
			body, rerr := readRespCapped(resp, probeBodyBytes)
			status := resp.StatusCode
			ct := resp.Header.Get("Content-Type")
			if rerr != nil {
				continue
			}
			if kind, at := classifyReflection(body, ct, marker, payload); kind != reflectNone {
				id := "web.reflected-input"
				if kind == reflectEscaped {
					id = "web.reflected-input-escaped"
				}
				f := p.Rules.NewFinding(id, p.AssetKey, loc(param), domain.Firm)
				f.Evidence = []domain.Evidence{red.TextEvidence("response", loc(param),
					"GET "+displayURL(base, param, payload)+"\n\n"+window(body, at))}
				if err := emit(f); err != nil {
					return st, err
				}
			}
			if err := p.checkErrorDisclosure(emit, red, page, base, param, payload, status, body, loc(param)); err != nil {
				return st, err
			}
			if redirectParamRe.MatchString(param) || valueIsURL(base.Query().Get(param)) {
				if st.Requests >= p.Budget {
					st.Truncated = true
					return st, nil
				}
				if p.OnProbeValue != nil {
					p.OnProbeValue(param, canaryOrigin)
				}
				if err := p.probeRedirect(ctx, &st, emit, red, base, param, loc(param)); err != nil {
					return st, err
				}
			}
		}
	}
	return st, nil
}

func (p *Prober) get(ctx context.Context, u *url.URL) (*http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	return p.Client.Do(req)
}

// probeRedirect places the canary origin in param and reports
// web.open-redirect when the server redirects there. The canary is read
// from the refused redirect, never followed.
func (p *Prober) probeRedirect(ctx context.Context, st *ProbeStats, emit engine.EmitFunc, red *safety.Redactor, base *url.URL, param, loc string) error {
	u := cloneWithParam(base, param, canaryOrigin)
	resp, err := p.get(ctx, u)
	st.Requests++
	if err != nil {
		if r, ok := safety.AsRedirectOutOfScope(err); ok && locationIsCanary(r.To) {
			f := p.Rules.NewFinding("web.open-redirect", p.AssetKey, loc, domain.Confirmed)
			f.Evidence = []domain.Evidence{red.TextEvidence("response", loc,
				"GET "+displayURL(base, param, canaryOrigin)+"\n\nredirects to an external host ("+canaryHostOnly(r.To)+", not followed)")}
			return emit(f)
		}
		return nil // dead end or unrelated refusal
	}
	defer func() { _ = resp.Body.Close() }()
	if locHdr := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && locationIsCanary(locHdr) {
		f := p.Rules.NewFinding("web.open-redirect", p.AssetKey, loc, domain.Confirmed)
		f.Evidence = []domain.Evidence{red.TextEvidence("response", loc,
			"GET "+displayURL(base, param, canaryOrigin)+"\n\nredirects to an external host ("+canaryHostOnly(locHdr)+", not followed)")}
		return emit(f)
	}
	_, _ = readRespCapped(resp, probeBodyBytes)
	return nil
}

func locationIsCanary(loc string) bool {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), canaryHost)
}

// canaryHostOnly renders just the redirect target's host for evidence:
// the full Location can echo discovery values (a token in the original
// query), while the host is the entire finding.
func canaryHostOnly(loc string) string {
	if u, err := url.Parse(strings.TrimSpace(loc)); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return canaryHost
}

func valueIsURL(v string) bool {
	if v == "" {
		return false
	}
	u, err := url.Parse(v)
	if err != nil || u.User != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

// checkErrorDisclosure reports web.error-disclosure when our quote broke
// the page (crawl status was not a 500) or surfaced an error signature on
// a page that rendered fine during the crawl. Pages already failing at
// crawl time are skipped: their errors pre-date the probe.
func (p *Prober) checkErrorDisclosure(emit engine.EmitFunc, red *safety.Redactor, page Page, base *url.URL, param, payload string, status int, body []byte, loc string) error {
	if page.Status >= 500 {
		return nil
	}
	matched := ""
	for _, re := range errorSignatures {
		if m := re.Find(body); m != nil {
			matched = string(m)
			break
		}
	}
	if status != 500 && matched == "" {
		return nil
	}
	f := p.Rules.NewFinding("web.error-disclosure", p.AssetKey, loc, domain.Tentative)
	summary := fmt.Sprintf("GET %s -> HTTP %d", displayURL(base, param, payload), status)
	if matched != "" {
		summary += "\n\n" + matched
	}
	f.Evidence = []domain.Evidence{red.TextEvidence("response", loc, summary)}
	return emit(f)
}

func (p *Prober) emitSessionInvalidated(emit engine.EmitFunc, red *safety.Redactor, loc string) error {
	f := p.Rules.NewFinding("web.session-invalidated", p.AssetKey, loc, domain.Firm)
	f.Evidence = []domain.Evidence{red.TextEvidence("response", loc,
		"server cleared the session cookie while probing "+loc+"; probe phase stopped")}
	return emit(f)
}

// isSessionClearedResp reports whether resp clears a session cookie: the
// cookie is set empty, expired, or with Max-Age 0.
func isSessionClearedResp(resp *http.Response, session []string) bool {
	if len(session) == 0 {
		return false
	}
	want := map[string]bool{}
	for _, n := range session {
		want[n] = true
	}
	now := time.Now()
	for _, c := range resp.Cookies() {
		if !want[c.Name] {
			continue
		}
		if c.Value == "" || c.MaxAge == 0 || (!c.Expires.IsZero() && !c.Expires.After(now)) {
			return true
		}
	}
	return false
}

// reflection classification.
type reflectKind int

const (
	reflectNone reflectKind = iota
	reflectHTML
	reflectEscaped
)

// classifyReflection decides whether a probe response shows unescaped
// HTML reflection (a finding), encoded reflection (informational), or
// nothing (JSON bodies, script literals, comments, absent markers).
func classifyReflection(body []byte, contentType, marker, payload string) (reflectKind, int) {
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return reflectNone, -1
	}
	if at := bytes.Index(body, []byte(payload)); at >= 0 {
		if reflectionContext(body, at) == contextHTML {
			return reflectHTML, at
		}
		return reflectNone, -1
	}
	if at := bytes.Index(body, []byte(marker)); at >= 0 && escapedNear(body, at+len(marker)) {
		return reflectEscaped, at
	}
	return reflectNone, -1
}

// reflection context kinds.
type reflectContext int

const (
	contextHTML reflectContext = iota
	contextElsewhere
)

// reflectionContext classifies where in the HTML the match sits: script
// string literals and comments are not HTML text/attribute contexts.
func reflectionContext(body []byte, at int) reflectContext {
	head := bytes.ToLower(body[:at])
	if insideRange(head, []byte("<script"), []byte("</script>")) {
		return contextElsewhere
	}
	if insideRange(head, []byte("<!--"), []byte("-->")) {
		return contextElsewhere
	}
	return contextHTML
}

// insideRange reports whether the last opener after the last closer means
// position len(head) sits inside an open region.
func insideRange(head, open, close []byte) bool {
	o := bytes.LastIndex(head, open)
	if o < 0 {
		return false
	}
	c := bytes.LastIndex(head, close)
	return c < o
}

// escapedNear reports whether an HTML entity follows the marker closely,
// meaning the application encoded the quotes.
func escapedNear(body []byte, after int) bool {
	end := after + 64
	if end > len(body) {
		end = len(body)
	}
	return entityRe.Match(body[after:end])
}

// window returns a ≤256-byte excerpt of body centred on at.
func window(body []byte, at int) string {
	start := at - probeEvidenceWindow/2
	if start < 0 {
		start = 0
	}
	end := start + probeEvidenceWindow
	if end > len(body) {
		end = len(body)
	}
	return string(body[start:end])
}

// cloneWithParam copies base with param set to value, keeping every other
// parameter untouched so the page renders as crawled.
func cloneWithParam(base *url.URL, param, value string) *url.URL {
	u := *base
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return &u
}

// displayURL shows the request line for evidence: the path with only the
// probed parameter, so echoed discovery values never reach evidence.
func displayURL(base *url.URL, param, value string) string {
	path := base.Path
	if path == "" {
		path = "/"
	}
	return path + "?" + url.QueryEscape(param) + "=" + url.QueryEscape(value)
}

// stableLocation is the finding location: origin + path + probed
// parameter name, with no values — least of all the random marker, which
// would churn fingerprints every scan.
func stableLocation(base *url.URL, param string) string {
	path := base.Path
	if path == "" {
		path = "/"
	}
	if param == "" {
		return base.Scheme + "://" + base.Host + path
	}
	return base.Scheme + "://" + base.Host + path + "?" + param
}
