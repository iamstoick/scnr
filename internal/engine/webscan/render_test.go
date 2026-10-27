package webscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/iamstoick/scnr/internal/safety"
)

// fakeRenderer serves canned post-JS HTML and records navigations.
type fakeRenderer struct {
	mu    sync.Mutex
	html  map[string]string
	calls []string
	err   error
}

func (f *fakeRenderer) Render(_ context.Context, targetURL string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, targetURL)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.html[targetURL]), nil
}

func (f *fakeRenderer) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// spaFixture serves a JS shell at / (no links statically) and a normal
// page at /static/.
func spaFixture() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script src="/app.js"></script></head><body><div id="root"></div></body></html>`))
	})
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/static/about">about</a></body></html>`))
	})
	return httptest.NewServer(mux)
}

func crawlWithRender(t *testing.T, srv *httptest.Server, seedPath string, render Renderer, scope func(string) bool) ([]string, CrawlStats) {
	t.Helper()
	o, _ := newOpts(t, nil, false, staticResolver{})
	seed := mustURL(t, srv.URL+seedPath)
	if scope == nil {
		scope = urlScopeFilter(seed, o)
	}
	c := &Crawler{Client: o.HTTP, Scope: scope, Limits: DefaultCrawlLimits(false), Origin: seed, Render: render}
	var visited []string
	st, err := c.Crawl(context.Background(), seed, func(p Page) error {
		visited = append(visited, p.URL)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return visited, st
}

func TestRenderFallbackDiscoversSPA(t *testing.T) {
	srv := spaFixture()
	defer srv.Close()
	fake := &fakeRenderer{html: map[string]string{
		srv.URL + "/": `<html><body><a href="/app">app</a><form action="/search" method="post"><input name="q"></form></body></html>`,
	}}
	visited, st := crawlWithRender(t, srv, "/", fake, nil)
	joined := strings.Join(visited, "\n")
	if !strings.Contains(joined, "/app") {
		t.Fatalf("rendered link not discovered: %v", visited)
	}
	if st.Rendered != 1 || len(fake.called()) != 1 {
		t.Fatalf("want exactly one render: %+v calls=%v", st, fake.called())
	}
}

func TestRenderSkippedWhenStaticFindsLinks(t *testing.T) {
	srv := spaFixture()
	defer srv.Close()
	fake := &fakeRenderer{html: map[string]string{}}
	visited, st := crawlWithRender(t, srv, "/static/", fake, nil)
	if st.Rendered != 0 || len(fake.called()) != 0 {
		t.Fatalf("renderer must not run when static parsing works: %+v", st)
	}
	if len(visited) == 0 {
		t.Fatal("static crawl found nothing")
	}
}

func TestRenderRespectsBudgetAndScope(t *testing.T) {
	srv := spaFixture()
	defer srv.Close()
	fake := &fakeRenderer{html: map[string]string{}}
	o, _ := newOpts(t, nil, false, staticResolver{})
	seed := mustURL(t, srv.URL+"/")
	denyAll := func(string) bool { return false }
	c := &Crawler{Client: o.HTTP, Scope: denyAll, Limits: DefaultCrawlLimits(false), Origin: seed, Render: fake, MaxRenders: 1}
	_, err := c.Crawl(context.Background(), seed, func(Page) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.called()) != 0 {
		t.Fatalf("out-of-scope URL must never render: %v", fake.called())
	}
}

func TestRenderAllowed(t *testing.T) {
	d := &safety.Dialer{}
	d.Pin("one.test", []netip.Addr{netip.MustParseAddr("93.184.216.34")})
	d.Pin("two.test", []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("93.184.216.35")})
	for name, tc := range map[string]struct {
		host string
		want bool
	}{
		"ip literal":   {host: "127.0.0.1", want: true},
		"single pin":   {host: "one.test", want: true},
		"multi pin":    {host: "two.test", want: false},
		"unpinned":     {host: "none.test", want: false},
		"empty dialer": {host: "none.test", want: false},
	} {
		dialer := d
		if name == "empty dialer" {
			dialer = nil
		}
		if got := renderAllowed(dialer, tc.host); got != tc.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

func TestFindBrowser(t *testing.T) {
	dir := t.TempDir()
	chrome := filepath.Join(dir, "chromium")
	if err := os.WriteFile(chrome, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if p, ok := FindBrowser(); !ok || p != chrome {
		t.Fatalf("got %q %v", p, ok)
	}
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if _, ok := FindBrowser(); ok {
		t.Fatal("found a browser on an empty PATH")
	}
}
