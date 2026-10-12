package webscan

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sync/semaphore"
)

// CrawlLimits bounds discovery. Deep doubles the first three.
type CrawlLimits struct {
	MaxDepth int
	MaxURLs  int
	MaxForms int
	MaxPairs int
}

// DefaultCrawlLimits returns the spec budgets (depth 3, 200 URLs, 50
// forms, 500 param pairs), doubled except pairs when deep.
func DefaultCrawlLimits(deep bool) CrawlLimits {
	l := CrawlLimits{MaxDepth: 3, MaxURLs: 200, MaxForms: 50, MaxPairs: 500}
	if deep {
		l.MaxDepth, l.MaxURLs, l.MaxForms = 6, 400, 100
	}
	return l
}

// maxSkippedLinks caps the destructive-link inventory; fetching is
// unaffected (everything destructive is skipped regardless).
const maxSkippedLinks = 500

// DefaultDenyWords matches URLs and link texts that look state-changing.
// Such links are inventoried and never fetched or probed. The list is a
// constant: with --auth-file it is mandatory and cannot be shrunk, and
// there is no knob anywhere that shrinks it.
var DefaultDenyWords = regexp.MustCompile(`(?i)\b(logout|signout|sign-out|log-out|delete|remove|destroy|purge|reset|disable|revoke|unsubscribe|cancel|approve|reject|publish|archive|wipe|format|shutdown|reboot)\b`)

// LooksDestructive reports whether rawURL or text trips the
// state-changing-word list (checked raw and percent-decoded).
func LooksDestructive(rawURL, text string) bool {
	if DefaultDenyWords.MatchString(rawURL) || DefaultDenyWords.MatchString(text) {
		return true
	}
	if dec, err := url.PathUnescape(rawURL); err == nil && dec != rawURL {
		return DefaultDenyWords.MatchString(dec)
	}
	return false
}

// Form is one inventoried HTML form: action, method and field names only.
// Values and hidden tokens are never recorded.
type Form struct {
	Action string
	Method string // "get" or "post" (lowercased; anything else treated as post)
	Fields []string
}

// Page is one crawled URL: its fetch status, query parameter names and
// POST forms.
type Page struct {
	URL    string
	Depth  int
	Status int // fetch status; 0 when unknown (hand-built pages)
	Params []string
	Forms  []Form
}

// SkippedLink is a discovered link the crawler refused to fetch because it
// looks state-changing. The engine turns these into web.state-changing-get.
type SkippedLink struct {
	URL  string
	Text string
}

// CrawlStats accounts the crawl. Truncated means a budget stopped
// discovery early (the engine emits web.crawl-truncated and a
// PartialError). Requests counts every fetch including robots.txt.
type CrawlStats struct {
	URLs      int
	Forms     int
	Pairs     int
	Requests  int
	Truncated bool
	Skipped   []SkippedLink
}

// Crawler discovers same-origin URLs, parameters and forms breadth-first.
type Crawler struct {
	Client *http.Client
	// Scope admits request URLs (urlScopeFilter); nil admits everything
	// and the transport still enforces scope per request.
	Scope  func(string) bool
	Limits CrawlLimits
	// Deny overrides the destructive-word list (tests); nil means
	// DefaultDenyWords. There is no user-facing override.
	Deny *regexp.Regexp
	// Origin anchors same-origin: every fetched URL must match its
	// scheme, host and port. Required.
	Origin *url.URL
	// Seeds are extra depth-1 starting points (template paths that
	// returned 2xx in the passive phase). They are screened like
	// discovered links (destructive ones inventoried, disallowed ones
	// dropped); only the primary seed is fetched unconditionally.
	Seeds []string
	// Robots overrides the fetched robots.txt (tests); nil fetches it.
	Robots *Robots
	Log    *slog.Logger
}

type crawlJob struct {
	u     *url.URL
	depth int
}

// Crawl fetches seed breadth-first and calls visit once per fetched page.
// Fetch failures are dead ends, not errors; only a cancelled context or a
// visit error aborts the crawl.
func (c *Crawler) Crawl(ctx context.Context, seed *url.URL, visit func(Page) error) (CrawlStats, error) {
	var st CrawlStats
	if c.Client == nil || c.Origin == nil {
		return st, fmt.Errorf("crawler needs a client and an origin")
	}
	deny := c.Deny
	if deny == nil {
		deny = DefaultDenyWords
	}
	robots := c.Robots
	if robots == nil {
		robots = c.fetchRobots(ctx, &st)
	}
	origin := originID(c.Origin)

	seen := map[string]bool{}      // exact: path + sorted param names
	collapsed := map[string]bool{} // numeric segments folded to {n}
	pairs := map[string]bool{}     // path + one param name
	skippedSeen := map[string]bool{}

	// The primary seed was explicitly authorised and is fetched
	// regardless. Extra seeds (2xx template paths) are screened like
	// discovered links: destructive ones are inventoried, disallowed
	// ones dropped.
	frontier := []crawlJob{{u: stripFragment(seed), depth: 0}}
	for _, s := range c.Seeds {
		u, err := url.Parse(s)
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if originID(u) != origin {
			continue
		}
		u = stripFragment(u)
		if destructiveMatch(deny, u.String(), "") {
			if !skippedSeen[u.String()] {
				skippedSeen[u.String()] = true
				if len(st.Skipped) < maxSkippedLinks {
					st.Skipped = append(st.Skipped, SkippedLink{URL: u.String()})
				}
			}
			continue
		}
		if robots.Disallowed(u.Path) {
			continue
		}
		frontier = append(frontier, crawlJob{u: u, depth: 1})
	}
	var mu sync.Mutex
	isTruncated := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return st.Truncated
	}
	// The numeric-collapse set is a second crawl-frontier dedupe so
	// /items/1..N is one node against the depth/URL budget; probing
	// still targets each page's real URL.
	reserve := func(key, fold string) bool {
		mu.Lock()
		defer mu.Unlock()
		if st.Truncated || seen[key] || collapsed[fold] {
			return false
		}
		if st.URLs >= c.Limits.MaxURLs {
			st.Truncated = true
			return false
		}
		seen[key] = true
		collapsed[fold] = true
		st.URLs++
		return true
	}

	for len(frontier) > 0 {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		var pages []Page
		var next []crawlJob
		var pm, nm sync.Mutex
		sem := semaphore.NewWeighted(requestParallel)
		var wg sync.WaitGroup
		for _, job := range frontier {
			if isTruncated() {
				break
			}
			if job.depth > c.Limits.MaxDepth {
				continue
			}
			key, fold, params := crawlKey(job.u)
			if !reserve(key, fold) {
				continue
			}
			mu.Lock()
			for _, p := range params {
				pairs[job.u.Path+"\x00"+p] = true
			}
			if len(pairs) > c.Limits.MaxPairs {
				st.Truncated = true
			}
			mu.Unlock()
			if isTruncated() {
				break
			}
			if err := sem.Acquire(ctx, 1); err != nil {
				wg.Wait()
				return st, err
			}
			wg.Add(1)
			go func(job crawlJob, params []string) {
				defer wg.Done()
				defer sem.Release(1)
				page, links, truncated := c.fetchPage(ctx, job, params, origin, robots, deny, pairs, skippedSeen, &mu, &st)
				mu.Lock()
				st.Requests++
				if truncated {
					st.Truncated = true
				}
				mu.Unlock()
				if page == nil {
					return
				}
				pm.Lock()
				pages = append(pages, *page)
				pm.Unlock()
				var child []crawlJob
				for _, l := range links {
					if job.depth+1 <= c.Limits.MaxDepth {
						child = append(child, crawlJob{u: l, depth: job.depth + 1})
					}
				}
				if len(child) > 0 {
					nm.Lock()
					next = append(next, child...)
					nm.Unlock()
				}
			}(job, params)
		}
		wg.Wait()
		for _, p := range pages {
			if err := visit(p); err != nil {
				return st, fmt.Errorf("visit %s: %w", p.URL, err)
			}
		}
		if st.Truncated {
			break
		}
		frontier = next
	}
	if c.Log != nil && st.Truncated {
		c.Log.Info("webscan: crawl stopped at a coverage cap", "urls", st.URLs, "forms", st.Forms, "pairs", st.Pairs)
	}
	mu.Lock()
	st.Pairs = len(pairs)
	mu.Unlock()
	return st, nil
}

// fetchPage fetches one URL and extracts links and forms. A nil page means
// a dead end (fetch failure, refusal, non-HTML with no params to report —
// no wait: every fetched URL is reported so its query params can be
// probed). truncated reports a forms/pairs cap hit during extraction.
func (c *Crawler) fetchPage(ctx context.Context, job crawlJob, params []string, origin string, robots *Robots, deny *regexp.Regexp, pairs, skippedSeen map[string]bool, mu *sync.Mutex, st *CrawlStats) (*Page, []*url.URL, bool) {
	page := &Page{URL: job.u.String(), Depth: job.depth, Params: params}
	rctx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, job.u.String(), nil)
	if err != nil {
		return nil, nil, false
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, nil, false // dead end: refused, DNS, reset
	}
	page.Status = resp.StatusCode
	body, err := readRespCapped(resp, maxBodyBytes)
	if err != nil {
		return nil, nil, false
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
		return page, nil, false // params still probed; nothing to discover
	}
	base, links, forms := extractLinks(body, job.u)
	if originID(base) != origin {
		base = job.u // off-origin <base href> is ignored, not followed
	}
	var out []*url.URL
	truncated := false
	for _, l := range links {
		u := resolveLink(base, l.href)
		if u == nil || u.User != nil {
			continue
		}
		if originID(u) != origin {
			continue
		}
		u.Fragment = ""
		// Destructive links are inventoried, never fetched or probed.
		// (Seeds never pass through here — frontier jobs are fetched
		// directly — so every discovered link is screened, including
		// depth-1 links found on the seed page. The prober re-screens
		// every page as well.)
		if destructiveMatch(deny, u.String(), l.text) {
			mu.Lock()
			if !skippedSeen[u.String()] {
				skippedSeen[u.String()] = true
				// Inventory is capped like every other crawl
				// product; beyond it links are still skipped,
				// just not individually recorded.
				if len(st.Skipped) < maxSkippedLinks {
					st.Skipped = append(st.Skipped, SkippedLink{URL: u.String(), Text: clippedText(l.text)})
				}
			}
			mu.Unlock()
			continue
		}
		if robots.Disallowed(u.Path) {
			continue
		}
		if c.Scope != nil && !c.Scope(u.String()) {
			continue
		}
		mu.Lock()
		for _, p := range queryParamNames(u) {
			pairs[u.Path+"\x00"+p] = true
		}
		if len(pairs) > c.Limits.MaxPairs {
			truncated = true
		}
		mu.Unlock()
		if truncated {
			break
		}
		out = append(out, u)
	}
	for _, f := range forms {
		mu.Lock()
		if st.Forms >= c.Limits.MaxForms {
			mu.Unlock()
			truncated = true
			break
		}
		st.Forms++
		mu.Unlock()
		if f.Method == "get" {
			// A GET form is a URL+param discovery, not an inventory item.
			if u := formGetURL(job.u, f); u != nil && originID(u) == origin {
				u.Fragment = ""
				if !robots.Disallowed(u.Path) && (c.Scope == nil || c.Scope(u.String())) {
					out = append(out, u)
				}
			}
			continue
		}
		page.Forms = append(page.Forms, f)
	}
	return page, out, truncated
}

func (c *Crawler) fetchRobots(ctx context.Context, st *CrawlStats) *Robots {
	u := *c.Origin
	u.Path = "/robots.txt"
	u.RawQuery = ""
	u.Fragment = ""
	rctx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil
	}
	st.Requests++
	body, err := readRespCapped(resp, 64<<10)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	return parseRobots(body)
}
