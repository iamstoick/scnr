package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/store"
)

func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	kev, err := os.ReadFile("../../testdata/vulndb/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	epss, err := os.ReadFile("../../testdata/vulndb/epss.csv")
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(epss)
	zw.Close()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			w.Write(kev)
		case "/epss.csv.gz":
			w.Write(gz.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestUpdateAndEnrich(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	s, _ := store.Open(":memory:")
	defer s.Close()
	ctx := context.Background()
	u := &Updater{Store: s, HTTP: srv.Client(), KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"}
	kev, epss, err := u.UpdateAll(ctx)
	if err != nil || kev != 2 || epss != 3 {
		t.Fatalf("kev=%d epss=%d err=%v", kev, epss, err)
	}
	metas, _ := s.VulnDBStatus(ctx)
	if metas[0].Version != "2026.10.09" || metas[1].Rows != 3 {
		t.Fatalf("%+v", metas)
	}
	e, err := NewEnricher(ctx, s)
	if err != nil || !e.Available {
		t.Fatal("enricher should be available")
	}
	f := domain.Finding{CVEs: []string{"CVE-2023-0001", "CVE-2021-44228"}}
	if err := e.Enrich(ctx, &f); err != nil {
		t.Fatal(err)
	}
	if !f.KEV || f.EPSS == nil || *f.EPSS != 0.97565 {
		t.Fatalf("enriched: kev=%v epss=%v", f.KEV, f.EPSS)
	}
	g := domain.Finding{CVEs: []string{"CVE-2023-0001"}}
	e.Enrich(ctx, &g)
	if g.KEV || *g.EPSS != 0.00012 {
		t.Fatalf("%+v", g)
	}
	// Bad URL fails cleanly and leaves old data in place.
	u.KEVURL = srv.URL + "/missing"
	if _, err := u.UpdateKEV(ctx); err == nil {
		t.Fatal("404 should fail")
	}
	if k, _ := s.LookupKEV(ctx, "CVE-2020-8203"); !k {
		t.Fatal("failed update must not wipe existing rows")
	}
}

func TestEnricherUnavailableIsNoop(t *testing.T) {
	s, _ := store.Open(":memory:")
	defer s.Close()
	e, _ := NewEnricher(context.Background(), s)
	if e.Available {
		t.Fatal("empty tables should be unavailable")
	}
	f := domain.Finding{CVEs: []string{"CVE-2021-44228"}}
	e.Enrich(context.Background(), &f)
	if f.KEV || f.EPSS != nil {
		t.Fatal("noop expected")
	}
}

func TestParseEPSSTolerant(t *testing.T) {
	entries, ver, err := ParseEPSS(bytes.NewBufferString("#v1\ncve,epss,percentile\nCVE-1,0.5,0.9\nbad,row\nCVE-2,x,y\n"))
	if err != nil || len(entries) != 1 || ver != "v1" {
		t.Fatalf("%v %q %v", entries, ver, err)
	}
	if _, _, err := ParseKEV(bytes.NewBufferString("{nope")); err == nil {
		t.Fatal("malformed KEV accepted")
	}
}

// A nil HTTP client is an error, never a default client (TestNoRawDialers
// keeps the literal out; this keeps the behaviour out).
func TestUpdaterNoClient(t *testing.T) {
	s, _ := store.Open(":memory:")
	defer s.Close()
	u := &Updater{Store: s, KEVURL: "http://127.0.0.1:1/kev.json", EPSSURL: "http://127.0.0.1:1/epss.csv.gz"}
	if _, _, err := u.UpdateAll(context.Background()); err == nil || !strings.Contains(err.Error(), "no HTTP client") {
		t.Fatalf("want no-client error, got %v", err)
	}
}
