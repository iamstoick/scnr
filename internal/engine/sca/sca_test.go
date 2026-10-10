package sca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/store"
)

func TestParseGoMod(t *testing.T) {
	src := `module example.com/x

go 1.22

require golang.org/x/text v0.3.0

require (
	github.com/a/b v1.2.3
	github.com/c/d v0.0.0-20200101000000-abcdef123456 // indirect
)
`
	pkgs, err := ParseGoMod("go.mod", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 || pkgs[0].Name != "golang.org/x/text" || pkgs[0].Version != "v0.3.0" || !pkgs[0].Direct || pkgs[2].Direct {
		t.Fatalf("%+v", pkgs)
	}
	if pkgs[1].PURL() != "pkg:golang/github.com/a/b@v1.2.3" {
		t.Fatalf("purl = %s", pkgs[1].PURL())
	}
}

func TestParsePackageLock(t *testing.T) {
	src := `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/@scope/b":{"version":"1.0.0","dev":true},"node_modules/link":{"link":true}}}`
	pkgs, err := ParsePackageLock("package-lock.json", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("%+v", pkgs)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if !byName["lodash"].Direct || byName["@scope/b"].Direct || byName["@scope/b"].PURL() != "pkg:npm/%40scope/b@1.0.0" {
		t.Fatalf("%+v", byName)
	}
	v1 := `{"lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.3.0"}}}`
	pkgs, _ = ParsePackageLock("package-lock.json", []byte(v1))
	if len(pkgs) != 1 || pkgs[0].Name != "left-pad" {
		t.Fatalf("v1 fallback: %+v", pkgs)
	}
	if _, err := ParsePackageLock("x", []byte("{not json")); err == nil {
		t.Fatal("malformed accepted")
	}
}

func TestParseRequirements(t *testing.T) {
	src := "# comment\nrequests==2.25.0\nflask>=2.0\nDjango[argon2]==4.2.1 ; python_version > '3'\n-r other.txt\nNumPy == 1.26.0  # pinned\n"
	pkgs, err := ParseRequirements("requirements.txt", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 || pkgs[0].Name != "requests" || pkgs[1].Name != "Django" || pkgs[1].Version != "4.2.1" || pkgs[2].Version != "1.26.0" || pkgs[2].Line != 6 {
		t.Fatalf("%+v", pkgs)
	}
	if pkgs[1].PURL() != "pkg:pypi/django@4.2.1" {
		t.Fatalf("purl = %s", pkgs[1].PURL())
	}
}

func TestCVSSv3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H": 5.9,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 3.3,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"garbage": 0,
	}
	for v, want := range cases {
		if got := cvssV3BaseScore(v); got != want {
			t.Errorf("%s = %v, want %v", v, got, want)
		}
	}
}

// fakeOSV serves a recorded querybatch + vuln detail response.
func fakeOSV(t *testing.T, calls *int32, fail429 int32) *httptest.Server {
	t.Helper()
	vuln := map[string]any{
		"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash", "details": "lodash before 4.17.21 is vulnerable. More text.",
		"aliases":  []string{"CVE-2020-8203"},
		"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}},
		"affected": []map[string]any{{
			"package": map[string]string{"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash"},
			"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "3.7.0"}, {"fixed": "4.17.19"}}}},
		}, {
			"package": map[string]string{"ecosystem": "npm", "name": "lodash"},
			"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}}},
		}},
		"references":        []map[string]string{{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw"}},
		"database_specific": map[string]any{"severity": "HIGH", "cwe_ids": []string{"CWE-1321"}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(calls, 1)
		if n <= fail429 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []batchQuery `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("bad querybatch body: %v", err)
			}
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				results[i] = map[string]any{"vulns": []any{}}
				if q.Package.Name == "lodash" && q.Version == "4.17.20" {
					results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-p6mc-m468-83gw"}}}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			json.NewEncoder(w).Encode(vuln)
		default:
			http.NotFound(w, r)
		}
	}))
}

func fixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"},"node_modules/left-pad":{"version":"1.3.0"}}}`), 0o600)
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.25.0\n"), 0o600)
	return dir
}

func TestEngineOnlineFindings(t *testing.T) {
	var calls int32
	srv := fakeOSV(t, &calls, 1) // first request gets a 429 to exercise retry
	defer srv.Close()
	st, _ := store.Open(":memory:")
	defer st.Close()
	client := &OSVClient{Base: srv.URL, HTTP: srv.Client(), Cache: st, Sleep: func(time.Duration) {}}
	e, err := New(client)
	if err != nil {
		t.Fatal(err)
	}
	dir := fixtureRepo(t)
	tgt := domain.Target{Type: domain.TargetPath, Value: dir}
	var out []domain.Finding
	err = e.Run(context.Background(), tgt, engine.Options{Online: true}, func(f domain.Finding) error { out = append(out, f); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(out), out)
	}
	f := out[0]
	if f.RuleID != "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20" {
		t.Fatalf("rule = %s", f.RuleID)
	}
	if !strings.Contains(f.HowToFix, "4.17.21") {
		t.Fatalf("HowToFix should name the fixed version above installed: %q", f.HowToFix)
	}
	if f.Severity != domain.High || f.CVSS == nil || f.CVSS.Score != 7.4 {
		t.Fatalf("severity/cvss: %v %+v", f.Severity, f.CVSS)
	}
	if len(f.CVEs) != 1 || f.CVEs[0] != "CVE-2020-8203" || f.CWE != "CWE-1321" {
		t.Fatalf("cves/cwe: %v %s", f.CVEs, f.CWE)
	}
	if f.Location != "package-lock.json" || f.AssetKey != "repo:"+dir {
		t.Fatalf("location/asset: %s %s", f.Location, f.AssetKey)
	}
	// Second run hits the vuln cache for details.
	before := atomic.LoadInt32(&calls)
	e.Run(context.Background(), tgt, engine.Options{Online: true}, func(domain.Finding) error { return nil })
	if atomic.LoadInt32(&calls)-before != 1 {
		t.Fatalf("expected only the querybatch call on the cached run, got %d", atomic.LoadInt32(&calls)-before)
	}
}

func TestEngineOfflineSkips(t *testing.T) {
	e, _ := New(&OSVClient{Base: "http://127.0.0.1:1"})
	dir := fixtureRepo(t)
	err := e.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: dir}, engine.Options{Online: false}, func(domain.Finding) error {
		t.Fatal("no findings offline")
		return nil
	})
	var skip *engine.SkipError
	if !errors.As(err, &skip) || skip.Reason != "offline" {
		t.Fatalf("want SkipError offline, got %v", err)
	}
	// Empty dir: nothing to do, not a skip.
	if err := e.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: t.TempDir()}, engine.Options{}, nil); err != nil {
		t.Fatalf("empty dir: %v", err)
	}
	p, err := e.Plan(context.Background(), domain.Target{Type: domain.TargetPath, Value: dir}, engine.Options{Online: true})
	if err != nil || !strings.Contains(p.Summary, "osv.dev") {
		t.Fatalf("plan: %+v %v", p, err)
	}
}

func TestOSVGivesUpAfterRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	c := &OSVClient{Base: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) {}}
	_, err := c.QueryBatch(context.Background(), []Package{{Ecosystem: "npm", Name: "x", Version: "1"}})
	if err == nil || !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("want retry exhaustion, got %v", err)
	}
	if _, err := c.GetVuln(context.Background(), "../etc"); err == nil {
		t.Fatal("bad id accepted")
	}
}

// Finding 9: Lookup sends at most MaxLookupPackages to OSV and reports the
// excess as a finding instead of dropping it silently; the per-file parsers
// stop at MaxLockEntries.
func TestLookupCapsPackages(t *testing.T) {
	var queries int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []batchQuery `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		atomic.AddInt64(&queries, int64(len(req.Queries)))
		results := make([]map[string]any, len(req.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": []any{}}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	defer srv.Close()
	e, _ := New(&OSVClient{Base: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) {}})
	const extra = 7
	pkgs := make([]Package, MaxLookupPackages+extra)
	for i := range pkgs {
		pkgs[i] = Package{Ecosystem: "npm", Name: "p" + strconv.Itoa(i), Version: "1.0.0", File: "package-lock.json"}
	}
	var out []domain.Finding
	err := e.Lookup(context.Background(), pkgs, "repo:/x", "sca", engine.Options{Online: true}, func(f domain.Finding) error { out = append(out, f); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&queries); got != MaxLookupPackages {
		t.Fatalf("OSV received %d queries, cap is %d", got, MaxLookupPackages)
	}
	if len(out) != 1 || out[0].RuleID != RuleLookupTruncated || !strings.Contains(out[0].Evidence[0].Redacted, strconv.Itoa(extra)+" not checked") {
		t.Fatalf("want one truncation finding naming the excess, got %+v", out)
	}
	// Under the cap: no note.
	out = nil
	if err := e.Lookup(context.Background(), pkgs[:10], "repo:/x", "sca", engine.Options{Online: true}, func(f domain.Finding) error { out = append(out, f); return nil }); err != nil || len(out) != 0 {
		t.Fatalf("%v %v", out, err)
	}

	var gomod, req, apk strings.Builder
	gomod.WriteString("module m\nrequire (\n")
	for i := 0; i < MaxLockEntries+10; i++ {
		fmt.Fprintf(&gomod, "\texample.com/m%d v1.0.0\n", i)
		fmt.Fprintf(&req, "pkg%d==1.0\n", i)
		fmt.Fprintf(&apk, "P:p%d\nV:1\n\n", i)
	}
	gomod.WriteString(")\n")
	if got, _ := ParseGoMod("go.mod", []byte(gomod.String())); len(got) != MaxLockEntries {
		t.Fatalf("go.mod kept %d", len(got))
	}
	if got, _ := ParseRequirements("requirements.txt", []byte(req.String())); len(got) != MaxLockEntries {
		t.Fatalf("requirements kept %d", len(got))
	}
	// Duplicates collapse like in the other parsers.
	if got, _ := ParseRequirements("requirements.txt", []byte("a==1\na==1\nb==2\n")); len(got) != 2 {
		t.Fatalf("requirements dedupe: %+v", got)
	}
	if got, _ := ParseGoMod("go.mod", []byte("require (\n\tx v1\n\tx v1\n)")); len(got) != 1 {
		t.Fatalf("go.mod dedupe: %+v", got)
	}
}

// Finding 1: a deeply nested YAML lockfile is refused on the raw bytes,
// before yaml.v3 can recurse into it (a stack overflow is fatal), including
// the "- - -" block form that nests without indentation.
func TestYAMLDepthPreScan(t *testing.T) {
	start := time.Now()
	for _, content := range [][]byte{
		bytes.Repeat([]byte("["), 5<<20),
		[]byte("packages:\n  " + strings.Repeat("- ", 1<<18) + "x\n"),
		[]byte("packages: " + strings.Repeat("{a: ", 20) + "1" + strings.Repeat("}", 20) + "\n"),
	} {
		if _, err := ParsePnpmLock("pnpm-lock.yaml", content); err == nil || !strings.Contains(err.Error(), "too deep") {
			t.Fatalf("deep yaml accepted: %v", err)
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("pre-scan too slow: %s", time.Since(start))
	}
	if got, err := ParsePnpmLock("pnpm-lock.yaml", []byte("lockfileVersion: '6.0'\npackages:\n  /lodash/4.17.20:\n    resolution: {integrity: sha512-x}\n    dev: false\n")); err != nil || len(got) != 1 {
		t.Fatalf("shallow flow mappings must still parse: %v %v", got, err)
	}
}

func FuzzParsers(f *testing.F) {
	f.Add([]byte("require (\n\tx v1\n)"))
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1"}}}`))
	f.Add([]byte("a==1\nb>=2\n"))
	f.Add([]byte("require (\n\tx v1\n\tx v1\n\ty v2\n)"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseGoMod("go.mod", b)
		ParsePackageLock("package-lock.json", b)
		ParseRequirements("requirements.txt", b)
	})
}
