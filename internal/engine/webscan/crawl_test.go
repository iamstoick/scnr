package webscan

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
)

// failResolve refuses every DNS lookup: these tests use IP literals only,
// so any lookup (notably for 169.254.169.254 or evil hosts) is a bug.
type failResolve struct{ t *testing.T }

func (f failResolve) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.t.Errorf("unexpected DNS lookup for %s", host)
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// TestCrawlerScope (D4): the crawler never leaves the origin or the scope:
// subdomains, other ports, off-origin <base>, refused redirects,
// protocol-relative and javascript: links are all dropped, and a
// URL-prefix scope binds discovery.
func TestCrawlerScope(t *testing.T) {
	var log requestLog
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
<a href="http://sub.127.0.0.1:1/">subdomain</a>
<a href="http://127.0.0.1:1/other-port">other port</a>
<a href="//evil.example/x">protocol relative</a>
<a href="javascript:alert(1)">js</a>
<a href="/redir">redirector</a>
<a href="/based">based</a>
<a href="/based2">based2</a>
<a href="/allowed/a">allowed</a>
<a href="/other">other</a>
</body></html>`))
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	})
	mux.HandleFunc("/based", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><base href="http://evil.example/sub/"></head><body><a href="/x">x</a></body></html>`))
	})
	mux.HandleFunc("/based2", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><base href="/sub/"></head><body><a href="y">y</a></body></html>`))
	})
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Write([]byte("x"))
	})
	mux.HandleFunc("/sub/y", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Write([]byte("y"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	o, _ := newOpts(t, nil, false, failResolve{t})
	seed := mustURL(t, srv.URL+"/")
	c := &Crawler{Client: o.HTTP, Scope: urlScopeFilter(seed, o), Limits: DefaultCrawlLimits(false), Origin: seed}
	var visited []string
	st, err := c.Crawl(context.Background(), seed, func(p Page) error {
		visited = append(visited, p.URL)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(visited, "\n")
	for _, want := range []string{srv.URL + "/", srv.URL + "/x", srv.URL + "/sub/y"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %v", want, visited)
		}
	}
	for _, v := range visited {
		u, _ := url.Parse(v)
		if u.Hostname() != "127.0.0.1" || u.Scheme != "http" {
			t.Errorf("escaped origin: %s", v)
		}
	}
	// The redirect target was refused before any dial: failResolve would
	// have fired, and nothing outside the origin was visited.
	if log.sawPath("/other-port") || strings.Contains(joined, "169.254.169.254") || strings.Contains(joined, "evil.example") {
		t.Fatalf("escaped: %v", visited)
	}
	_ = st

	// URL-prefix scope binds discovery.
	seed2 := mustURL(t, srv.URL+"/")
	admit := func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/allowed/") || raw == srv.URL+"/" }
	c2 := &Crawler{Client: o.HTTP, Scope: admit, Limits: DefaultCrawlLimits(false), Origin: seed2}
	visited = nil
	if _, err := c2.Crawl(context.Background(), seed2, func(p Page) error {
		visited = append(visited, p.URL)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, v := range visited {
		if v != srv.URL+"/" && !strings.HasPrefix(v, srv.URL+"/allowed/") {
			t.Errorf("outside prefix: %s", v)
		}
	}
}

// TestCrawlerCaps (D4): a 10,000-link calendar stops at exactly 200 URLs
// with Truncated set; ?page=N is one node; /items/N collapses to one node.
func TestCrawlerCaps(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 1; i <= 10000; i++ {
			fmt.Fprintf(&b, `<a href="/event-link-%d">e</a>`, i)
		}
		b.WriteString("</body></html>")
		w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/event-link-", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>e</body></html>"))
	})
	mux.HandleFunc("/paged", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 1; i <= 500; i++ {
			fmt.Fprintf(&b, `<a href="/paged?page=%d">p</a>`, i)
		}
		b.WriteString("</body></html>")
		w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/items/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 1; i <= 500; i++ {
			fmt.Fprintf(&b, `<a href="/items/%d">i</a>`, i)
		}
		b.WriteString("</body></html>")
		w.Write([]byte(b.String()))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	o, _ := newOpts(t, nil, false, staticResolver{})

	crawl := func(seedPath string) CrawlStats {
		seed := mustURL(t, srv.URL+seedPath)
		c := &Crawler{Client: o.HTTP, Scope: urlScopeFilter(seed, o), Limits: DefaultCrawlLimits(false), Origin: seed}
		st, err := c.Crawl(context.Background(), seed, func(Page) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	cal := crawl("/")
	if cal.URLs != 200 || !cal.Truncated {
		t.Fatalf("calendar: %+v", cal)
	}
	paged := crawl("/paged")
	if paged.URLs != 2 || paged.Truncated { // /paged + one ?page node
		t.Fatalf("paged: %+v", paged)
	}
	items := crawl("/items/")
	if items.URLs != 2 || items.Truncated { // /items/ + one collapsed node
		t.Fatalf("items: %+v", items)
	}
}

// TestCrawlerHonoursRobots: Disallow is honoured for discovered links but
// not for the explicitly authorised seed.
func TestCrawlerHonoursRobots(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /secret/\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/secret/x">s</a><a href="/pub">p</a></body></html>`))
	})
	mux.HandleFunc("/secret/x", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("s"))
	})
	mux.HandleFunc("/pub", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("p"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	o, _ := newOpts(t, nil, false, staticResolver{})

	seed := mustURL(t, srv.URL+"/")
	c := &Crawler{Client: o.HTTP, Scope: urlScopeFilter(seed, o), Limits: DefaultCrawlLimits(false), Origin: seed}
	var visited []string
	if _, err := c.Crawl(context.Background(), seed, func(p Page) error {
		visited = append(visited, p.URL)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(visited, "\n")
	if strings.Contains(joined, "/secret/") {
		t.Fatalf("robots ignored: %v", visited)
	}
	if !strings.Contains(joined, "/pub") {
		t.Fatalf("allowed page missed: %v", visited)
	}

	// The seed itself is exempt: the operator named it explicitly.
	seed2 := mustURL(t, srv.URL+"/secret/x")
	c2 := &Crawler{Client: o.HTTP, Scope: urlScopeFilter(seed2, o), Limits: DefaultCrawlLimits(false), Origin: seed2}
	visited = nil
	if _, err := c2.Crawl(context.Background(), seed2, func(p Page) error {
		visited = append(visited, p.URL)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(visited) != 1 {
		t.Fatalf("seed not fetched: %v", visited)
	}
}

// TestDestructiveLinksNotFetched (D5): logout/delete links (raw and
// encoded) are inventoried and never requested; the prober also refuses
// to probe destructive page URLs.
func TestDestructiveLinksNotFetched(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// Backstop: any destructive fetch trips here even if mux
			// escaping semantics change which handler matches.
			if strings.Contains(strings.ToLower(r.URL.EscapedPath()), "ogout") || strings.Contains(r.URL.EscapedPath(), "delete") {
				t.Errorf("destructive URL requested: %s", r.URL.EscapedPath())
			}
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/logout">Logout</a><a href="/items/1/delete">x</a><a href="/%6Cogout">y</a><a href="/ok">ok</a></body></html>`))
	})
	// Note: no "/%6Cogout" handler — Go's mux treats it as conflicting
	// with "/logout". The "/" backstop above trips if the encoded link
	// is ever requested.
	for _, p := range []string{"/logout", "/items/1/delete", "/ok"} {
		p := p
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if p != "/ok" {
				t.Errorf("destructive URL requested: %s", r.URL.Path)
			}
			w.Write([]byte("ok"))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	o, _ := newOpts(t, nil, false, staticResolver{})
	seed := mustURL(t, srv.URL+"/")
	c := &Crawler{Client: o.HTTP, Scope: urlScopeFilter(seed, o), Limits: DefaultCrawlLimits(false), Origin: seed}
	st, err := c.Crawl(context.Background(), seed, func(Page) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Skipped) != 3 {
		t.Fatalf("skipped: %+v", st.Skipped)
	}

	// Prober-level: a destructive page URL is never probed.
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rules := e.rules
	p := &Prober{Client: o.HTTP, Budget: 100, Rules: rules, Red: o.Redactor}
	pst, err := p.Probe(context.Background(), []Page{{URL: srv.URL + "/logout?x=1", Params: []string{"x"}}}, func(domain.Finding) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if pst.Requests != 0 {
		t.Fatalf("probed a destructive URL: %+v", pst)
	}
}

// TestCrawlerScreensSeeds: extra seeds are screened like discovered
// links — destructive ones are inventoried, robots-disallowed ones
// dropped — while the primary seed is always fetched.
func TestCrawlerScreensSeeds(t *testing.T) {
	var log requestLog
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /secret/\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>root</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	o, _ := newOpts(t, nil, false, staticResolver{})
	seed := mustURL(t, srv.URL+"/")
	c := &Crawler{Client: o.HTTP, Scope: urlScopeFilter(seed, o), Limits: DefaultCrawlLimits(false), Origin: seed,
		Seeds: []string{srv.URL + "/logout", srv.URL + "/secret/x", srv.URL + "/ok?x=1"}}
	var visited []string
	st, err := c.Crawl(context.Background(), seed, func(p Page) error {
		visited = append(visited, p.URL)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(visited, "\n")
	if !strings.Contains(joined, srv.URL+"/") || !strings.Contains(joined, "/ok?x=1") {
		t.Fatalf("visited: %v", visited)
	}
	if strings.Contains(joined, "/logout") || strings.Contains(joined, "/secret/") {
		t.Fatalf("unscreened seed visited: %v", visited)
	}
	if len(st.Skipped) != 1 || !strings.Contains(st.Skipped[0].URL, "/logout") {
		t.Fatalf("skipped: %+v", st.Skipped)
	}
	for _, q := range log.all() {
		if strings.Contains(q.url, "logout") || strings.Contains(q.url, "/secret/") {
			t.Fatalf("requested: %s", q.url)
		}
	}
}

// TestCrawlerGetForms: method=get forms become URL+param discoveries;
// method=post forms are inventoried with field names only.
func TestCrawlerGetForms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
<form action="/find" method="get"><input name="q"><input name="lang" value="en"></form>
<form action="/save" method="post"><input name="t"><input type="hidden" name="csrf" value="tok"></form>
</body></html>`))
	})
	mux.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("found"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	o, _ := newOpts(t, nil, false, staticResolver{})
	seed := mustURL(t, srv.URL+"/")
	c := &Crawler{Client: o.HTTP, Scope: urlScopeFilter(seed, o), Limits: DefaultCrawlLimits(false), Origin: seed}
	var pages []Page
	if _, err := c.Crawl(context.Background(), seed, func(p Page) error {
		pages = append(pages, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var found *Page
	for i := range pages {
		if strings.HasPrefix(pages[i].URL, srv.URL+"/find") {
			found = &pages[i]
		}
	}
	if found == nil || strings.Join(found.Params, ",") != "lang,q" {
		t.Fatalf("GET form not discovered: %+v", pages)
	}
	if len(pages[0].Forms) != 1 || pages[0].Forms[0].Action != "/save" || strings.Join(pages[0].Forms[0].Fields, ",") != "t,csrf" {
		t.Fatalf("POST form: %+v", pages[0].Forms)
	}
}
