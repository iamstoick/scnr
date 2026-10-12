package webscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
)

// TestPayloadRuntime (D1, runtime half): every value the prober sets
// matches the alphabet or is the fixed canary origin; discovered
// parameter values are echoed back untouched so pages render as crawled.
func TestPayloadRuntime(t *testing.T) {
	var mu sync.Mutex
	var seen [][2]string // (q, keep) per request
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, [2]string{r.URL.Query().Get("q"), r.URL.Query().Get("keep")})
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>none here</body></html>"))
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o, _ := newOpts(t, nil, false, staticResolver{})
	var values []string
	p := &Prober{Client: o.HTTP, Budget: 100, Rules: e.rules, Red: o.Redactor, AssetKey: "url:" + srv.URL,
		OnProbeValue: func(param, value string) { values = append(values, value) }}
	pages := []Page{
		{URL: srv.URL + "/search?q=x&keep=1", Params: []string{"keep", "q"}, Status: 200},
		{URL: srv.URL + "/go?next=/home", Params: []string{"next"}, Status: 302},
	}
	st, err := p.Probe(context.Background(), pages, func(domain.Finding) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 4 { // q, keep, next-reflect, next-canary
		t.Fatalf("requests: %+v", st)
	}
	for _, v := range values {
		if v != canaryOrigin && !AllowedPayloadRe.MatchString(v) {
			t.Fatalf("out-of-alphabet value: %q", v)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected 2 search probes, saw %d", len(seen))
	}
	// Each probe sets exactly one parameter to a payload; the other
	// keeps its crawled value so the page renders as discovered.
	for _, pair := range seen {
		qIsPayload := AllowedPayloadRe.MatchString(pair[0])
		keepIsPayload := AllowedPayloadRe.MatchString(pair[1])
		if qIsPayload == keepIsPayload {
			t.Fatalf("expected exactly one payload per request: %q", pair)
		}
		if !qIsPayload && pair[0] != "x" {
			t.Fatalf("q not preserved: %q", pair)
		}
		if !keepIsPayload && pair[1] != "1" {
			t.Fatalf("keep not preserved: %q", pair)
		}
	}
}

// TestSessionInvalidated: when the server clears the session cookie,
// probing stops with web.session-invalidated instead of continuing
// anonymously.
func TestSessionInvalidated(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, "/a")
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Set-Cookie", "session=; Path=/; Max-Age=0")
		w.Write([]byte("<html><body>a</body></html>"))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, "/b")
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>b</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o, _ := newOpts(t, nil, false, staticResolver{})
	p := &Prober{Client: o.HTTP, Budget: 100, Rules: e.rules, Red: o.Redactor, AssetKey: "x", SessionCookies: []string{"session"}}
	var ids []string
	st, err := p.Probe(context.Background(), []Page{
		{URL: srv.URL + "/a?q=1", Params: []string{"q"}, Status: 200},
		{URL: srv.URL + "/b?q=1", Params: []string{"q"}, Status: 200},
	}, func(f domain.Finding) error { ids = append(ids, f.RuleID); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !st.SessionInvalidated {
		t.Fatalf("stats: %+v", st)
	}
	if len(ids) != 1 || ids[0] != "web.session-invalidated" {
		t.Fatalf("findings: %v", ids)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 1 || hits[0] != "/a" {
		t.Fatalf("probing continued: %v", hits)
	}
}

// TestProbeBudgetExact: the budget stops probing mid-list with Truncated
// set and no partial request.
func TestProbeBudgetExact(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>ok</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	o, _ := newOpts(t, nil, false, staticResolver{})
	p := &Prober{Client: o.HTTP, Budget: 3, Rules: e.rules, Red: o.Redactor, AssetKey: "x"}
	st, err := p.Probe(context.Background(), []Page{
		{URL: srv.URL + "/?a=1", Params: []string{"a"}, Status: 200},
		{URL: srv.URL + "/?b=1", Params: []string{"b"}, Status: 200},
		{URL: srv.URL + "/?c=1", Params: []string{"c"}, Status: 200},
		{URL: srv.URL + "/?d=1", Params: []string{"d"}, Status: 200},
	}, func(domain.Finding) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 3 || !st.Truncated {
		t.Fatalf("stats: %+v", st)
	}
}

// FuzzCrawlerHTML feeds hostile HTML into the link extractor: no panic,
// no error, and field names stay sane.
func FuzzCrawlerHTML(f *testing.F) {
	f.Add("<a href=\"/x\">y</a>")
	f.Add("<form action=\"/s\" method=\"post\"><input name=\"u\"></form>")
	f.Add("<base href=\"http://evil.example/\"><a href=\"/x\">y</a>")
	f.Add(strings.Repeat("<a href=\"/a\">", 1000))
	f.Add("\x00\x01\x02<>\"'&=")
	f.Add("<a href=\"\" \x00>")
	f.Fuzz(func(t *testing.T, body string) {
		page := mustURL(t, "https://app.example/dir/p?q=1")
		base, links, forms := extractLinks([]byte(body), page)
		if base == nil {
			t.Fatal("nil base")
		}
		for _, l := range links {
			_ = resolveLink(base, l.href)
			if len(l.text) > maxLinkText {
				t.Fatalf("text not clipped: %d", len(l.text))
			}
		}
		for _, fm := range forms {
			if fm.Method != "get" && fm.Method != "post" {
				t.Fatalf("method %q", fm.Method)
			}
			for _, name := range fm.Fields {
				if name == "" || len(name) > 4096 {
					t.Fatalf("field %q", name)
				}
			}
		}
		_ = crawlKeyForFuzz(page)
	})
}

func crawlKeyForFuzz(u *url.URL) string {
	k, _, _ := crawlKey(u)
	return k
}
