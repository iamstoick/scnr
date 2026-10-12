package webscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
)

// loggedRequest is one server-side observation.
type loggedRequest struct {
	method string
	url    string
	body   int
	header http.Header
}

type requestLog struct {
	mu   sync.Mutex
	reqs []loggedRequest
}

func (l *requestLog) record(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, loggedRequest{method: r.Method, url: r.URL.String(), body: int(r.ContentLength), header: r.Header.Clone()})
}

func (l *requestLog) all() []loggedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]loggedRequest(nil), l.reqs...)
}

func (l *requestLog) sawPath(path string) bool {
	for _, q := range l.all() {
		if strings.HasPrefix(q.url, path) {
			return true
		}
	}
	return false
}

// fixtureApp is the acceptance-test web app: a reflective parameter, an
// open redirect, a SQL error page, logout/delete links, a POST form, a
// 300-link index, plus JSON/script/attribute reflectors for D8.
func fixtureApp(t *testing.T, log *requestLog) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
<a href="/search?q=hi">search</a>
<a href="/go?next=/home">go</a>
<a href="/item?id=5">item</a>
<a href="/json?q=x">json</a>
<a href="/script?q=y">script</a>
<a href="/attr?name=z">attr</a>
<a href="/logout">Log out</a>
<a href="/items/1/delete">remove</a>
<a href="/index">index</a>
<form action="/submit" method="post"><input name="u"><input name="pw"></form>
</body></html>`)
	})
	mux.HandleFunc("/index", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 1; i <= 300; i++ {
			fmt.Fprintf(&b, `<a href="/node-%d">n%d</a> `, i, i)
		}
		b.WriteString("</body></html>")
		w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/node-", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>node</body></html>"))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>results for %s</p></body></html>", r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/attr", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><input value="%s"></body></html>`, r.URL.Query().Get("name"))
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"q": "%s"}`, r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/script", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><script>var q="%s";</script><p>ok</p></html>`, r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("You have an error in your SQL syntax near ''1''"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>item</body></html>"))
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		t.Error("/logout was requested")
	})
	mux.HandleFunc("/items/1/delete", func(w http.ResponseWriter, r *http.Request) {
		t.Error("/items/1/delete was requested")
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		t.Error("POST form was submitted")
	})
	mux.HandleFunc("/submit-intrusive", func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Write([]byte("ok"))
	})
	return mux
}

// intrusiveTarget builds the URL target + options for fixture runs. The
// empty static resolver fails every DNS lookup instantly (all fixture
// hosts are literals), so the canary redirect refusal is fast.
func intrusiveTarget(t *testing.T, srvURL string) (domain.Target, engine.Options) {
	t.Helper()
	o, _ := newOpts(t, nil, false, staticResolver{})
	tgt := domain.Target{Raw: srvURL, Type: domain.TargetURL, Value: srvURL + "/", Hostname: "127.0.0.1"}
	return tgt, o
}

// TestIntrusiveFixture (acceptance 5.6.1): a full intrusive run finds the
// reflective param, the open redirect, the SQL error page, the
// state-changing links and the POST form; the 300-link index truncates
// the crawl; /logout is never requested; probes stay within budget.
func TestIntrusiveFixture(t *testing.T) {
	var log requestLog
	srv := httptest.NewServer(fixtureApp(t, &log))
	defer srv.Close()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tgt, o := intrusiveTarget(t, srv.URL)
	o.Intrusive = true
	var stats engine.Stats
	o.Stats = func(s engine.Stats) { stats = s }
	got, err := collect(t, e, tgt, o)
	if err == nil {
		t.Fatal("expected partial error from the truncated crawl")
	}
	if pe, ok := err.(*engine.PartialError); !ok || !strings.Contains(pe.Reason, "crawl cap") {
		t.Fatalf("err: %v", err)
	}
	for _, want := range []string{"web.reflected-input", "web.open-redirect", "web.error-disclosure", "web.state-changing-get", "web.form-inventory", "web.crawl-truncated"} {
		if len(got[want]) == 0 {
			t.Errorf("missing %s (have %v)", want, ruleIDs(got))
		}
	}
	if len(got["web.state-changing-get"]) != 2 {
		t.Errorf("state-changing links: %d", len(got["web.state-changing-get"]))
	}
	if len(got["web.reflected-input"]) != 2 { // /search text + /attr attribute
		t.Errorf("reflected-input: %d", len(got["web.reflected-input"]))
	}
	if len(got["web.probe-truncated"]) != 0 {
		t.Error("probe budget should hold on this fixture")
	}
	if log.sawPath("/logout") || log.sawPath("/items/1/delete") || log.sawPath("/submit?") || log.sawPath("/submit ") {
		t.Fatal("state-changing URL requested")
	}
	for _, q := range log.all() {
		if strings.Contains(q.url, "/submit") && !strings.Contains(q.url, "submit-intrusive") {
			t.Fatalf("form submitted: %s", q.url)
		}
	}
	if stats.Probes == 0 || stats.Probes > 1000 {
		t.Fatalf("probes: %d", stats.Probes)
	}
	if stats.Crawl != 201 { // 200 URL budget + robots.txt
		t.Fatalf("crawl requests: %d", stats.Crawl)
	}
	// Locations carry no values and no markers (fingerprint stability).
	for _, f := range got["web.reflected-input"] {
		if strings.Contains(f.Location, "scnr") || strings.Contains(f.Location, "=") {
			t.Fatalf("unstable location: %q", f.Location)
		}
	}
}

func ruleIDs(got map[string][]domain.Finding) []string {
	var out []string
	for id := range got {
		out = append(out, id)
	}
	return out
}

// TestPassiveOnlyWithoutFlag (acceptance 5.6.2): without --allow-intrusive
// the same fixture gets Phase 3 behaviour only: no active findings, no
// marker traffic, no error.
func TestPassiveOnlyWithoutFlag(t *testing.T) {
	var log requestLog
	srv := httptest.NewServer(fixtureApp(t, &log))
	defer srv.Close()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tgt, o := intrusiveTarget(t, srv.URL)
	var stats engine.Stats
	o.Stats = func(s engine.Stats) { stats = s }
	got, err := collect(t, e, tgt, o)
	if err != nil {
		t.Fatal(err)
	}
	for id := range got {
		if strings.HasSuffix(id, "-truncated") || id == "web.reflected-input" || id == "web.open-redirect" ||
			id == "web.error-disclosure" || id == "web.state-changing-get" || id == "web.form-inventory" ||
			id == "web.session-invalidated" || id == "web.reflected-input-escaped" {
			t.Errorf("active finding without the flag: %s", id)
		}
	}
	if stats != (engine.Stats{}) {
		t.Fatalf("stats: %+v", stats)
	}
	for _, q := range log.all() {
		if strings.Contains(q.url, "scnr") {
			t.Fatalf("marker traffic without the flag: %s", q.url)
		}
	}
}

// TestActiveMethods (D2): over a full intrusive run every request is
// GET/HEAD except intrusive-template POSTs, all ≤ 4 KiB; and the POST
// template does not run without the flag.
func TestActiveMethods(t *testing.T) {
	var log requestLog
	srv := httptest.NewServer(fixtureApp(t, &log))
	defer srv.Close()
	dir := t.TempDir()
	tpl := "id: intrusive-post-probe\ninfo:\n  title: T\n  severity: low\n  what: w\n  why: y\n  fix: f\nsafety: intrusive\nhttp:\n  - method: POST\n    path: [\"/submit-intrusive\"]\n    body: \"a=1\"\n    matchers:\n      - type: status\n        status: [200]\n"
	writeFile(t, dir+"/probe.yaml", tpl)
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	run := func(intrusive bool) {
		log.reqs = nil
		tgt, o := intrusiveTarget(t, srv.URL)
		o.Intrusive = intrusive
		o.TemplatesDir = dir
		_, _ = collect(t, e, tgt, o)
	}
	run(true)
	posts := 0
	for _, q := range log.all() {
		switch q.method {
		case http.MethodGet, http.MethodHead:
		case http.MethodPost:
			posts++
			if q.body > 4096 {
				t.Fatalf("POST body %d bytes", q.body)
			}
		default:
			t.Fatalf("method %s", q.method)
		}
	}
	if posts == 0 {
		t.Fatal("intrusive POST template never ran")
	}
	run(false)
	for _, q := range log.all() {
		if q.method == http.MethodPost {
			t.Fatal("intrusive POST ran without the flag")
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
