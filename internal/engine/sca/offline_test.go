package sca

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/store"
)

// stageVulns loads OSV records into an in-memory store the way the bundle
// loader does (RecordsFromVuln -> Row -> staged swap).
func stageVulns(t *testing.T, st *store.Store, ecosystem string, vulns ...*Vuln) {
	t.Helper()
	ctx := context.Background()
	load, err := st.BeginOfflineLoad(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vulns {
		for _, r := range RecordsFromVuln(v, ecosystem) {
			if err := load.Stage(ctx, r.Row()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := load.Commit(ctx, "test"); err != nil {
		t.Fatal(err)
	}
}

func fingerprints(fs []domain.Finding) []string {
	var out []string
	for _, f := range fs {
		if strings.HasPrefix(f.RuleID, "sca.osv.") {
			out = append(out, f.Fingerprint)
		}
	}
	sort.Strings(out)
	return out
}

// A4: the same lockfiles yield identical sca.osv.* fingerprints through the
// recorded OSV server and through a bundle built from the same record.
func TestOfflineMatchesOnline(t *testing.T) {
	var calls int32
	srv := fakeOSV(t, &calls, 0)
	defer srv.Close()
	st, _ := store.Open(":memory:")
	defer st.Close()
	online := &OSVClient{Base: srv.URL, HTTP: srv.Client(), Cache: st, Sleep: func(time.Duration) {}}
	e, err := New(online)
	if err != nil {
		t.Fatal(err)
	}
	dir := fixtureRepo(t)
	tgt := domain.Target{Type: domain.TargetPath, Value: dir}
	var onlineOut []domain.Finding
	if err := e.Run(context.Background(), tgt, engine.Options{Online: true}, func(f domain.Finding) error { onlineOut = append(onlineOut, f); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(fingerprints(onlineOut)) != 1 {
		t.Fatalf("online fixture should yield one finding: %+v", onlineOut)
	}

	// Build the bundle rows from the very record the server returned.
	v, err := online.GetVuln(context.Background(), "GHSA-p6mc-m468-83gw")
	if err != nil {
		t.Fatal(err)
	}
	stageVulns(t, st, "npm", v)
	e.Offline = &OfflineClient{Store: st}
	var offlineOut []domain.Finding
	if err := e.Run(context.Background(), tgt, engine.Options{Online: false}, func(f domain.Finding) error { offlineOut = append(offlineOut, f); return nil }); err != nil {
		t.Fatalf("offline run: %v", err)
	}
	if on, off := fingerprints(onlineOut), fingerprints(offlineOut); strings.Join(on, ",") != strings.Join(off, ",") {
		t.Fatalf("fingerprints differ\nonline:  %v\noffline: %v", on, off)
	}
	f := offlineOut[0]
	if f.RuleID != "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20" || !strings.Contains(f.HowToFix, "4.17.21") || f.Severity != domain.High || f.CWE != "CWE-1321" {
		t.Fatalf("offline finding: %+v", f)
	}
	for _, f := range offlineOut {
		if f.RuleID == RuleVersionUnparsed {
			t.Fatal("fixture versions are valid semver; no unparsed finding expected")
		}
	}
	p, err := e.Plan(context.Background(), tgt, engine.Options{Online: false})
	if err != nil || !strings.Contains(p.Summary, "local OSV bundle") || p.Network {
		t.Fatalf("offline plan: %+v %v", p, err)
	}
}

// Without rows the engine is skipped exactly as before Phase 4a.
func TestOfflineEmptyStoreSkips(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	e, _ := New(&OSVClient{Base: "http://127.0.0.1:1"})
	e.Offline = &OfflineClient{Store: st}
	dir := fixtureRepo(t)
	err := e.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: dir}, engine.Options{}, func(domain.Finding) error {
		t.Fatal("no findings expected")
		return nil
	})
	var skip *engine.SkipError
	if !errors.As(err, &skip) || skip.Reason != SkipReasonOffline {
		t.Fatalf("want SkipError offline, got %v", err)
	}
	p, _ := e.Plan(context.Background(), domain.Target{Type: domain.TargetPath, Value: dir}, engine.Options{})
	if !strings.Contains(p.Summary, "no bundle loaded") {
		t.Fatalf("plan: %+v", p)
	}
}

// An installed version that is not semver in a semver ecosystem is not
// reported as affected and is surfaced as sca.version-unparsed.
func TestOfflineUnparsedVersion(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	var v Vuln
	raw, _ := json.Marshal(map[string]any{"id": "GHSA-aaaa-bbbb-cccc", "summary": "x", "affected": []map[string]any{{
		"package": map[string]string{"ecosystem": "npm", "name": "weird"},
		"ranges":  []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}}}},
	}}})
	json.Unmarshal(raw, &v)
	stageVulns(t, st, "npm", &v)
	e, _ := New(nil)
	e.Offline = &OfflineClient{Store: st}
	pkgs := []Package{{Ecosystem: "npm", Name: "weird", Version: "git+https://example.com/x#abc", File: "package-lock.json"}, {Ecosystem: "npm", Name: "weird", Version: "1.0.0", File: "package-lock.json"}}
	var out []domain.Finding
	if err := e.Lookup(context.Background(), pkgs, "repo:x", Name, engine.Options{}, func(f domain.Finding) error { out = append(out, f); return nil }); err != nil {
		t.Fatal(err)
	}
	var unparsed, vuln int
	for _, f := range out {
		switch {
		case f.RuleID == RuleVersionUnparsed:
			unparsed++
			if f.Severity != domain.Info || !strings.Contains(f.Evidence[0].Redacted, "weird@git+https") {
				t.Fatalf("unparsed finding: %+v", f)
			}
		case strings.HasPrefix(f.RuleID, "sca.osv."):
			vuln++
			if !strings.Contains(f.RuleID, "@1.0.0") {
				t.Fatalf("the unparsable version must not match: %s", f.RuleID)
			}
		}
	}
	if unparsed != 1 || vuln != 1 {
		t.Fatalf("unparsed=%d vuln=%d: %+v", unparsed, vuln, out)
	}
}

func TestAffects(t *testing.T) {
	rng := func(typ string, evs ...Event) Range { return Range{Type: typ, Events: evs} }
	two := []Range{rng("SEMVER", Event{Introduced: "1.0.0"}, Event{Fixed: "1.5.0"}, Event{Introduced: "2.0.0"}, Event{Fixed: "2.3.0"})}
	// The same two intervals with the events listed out of order (the
	// reviewer's case): a naive in-order walk closes the second interval
	// with the first one's fixed boundary and misses 2.1.0.
	twoUnsorted := []Range{rng("SEMVER", Event{Introduced: "2.0.0"}, Event{Fixed: "2.3.0"}, Event{Introduced: "1.0.0"}, Event{Fixed: "1.5.0"})}
	twoLast := []Range{rng("SEMVER", Event{Introduced: "1.0.0"}, Event{LastAffected: "1.5.0"}, Event{Introduced: "2.0.0"}, Event{LastAffected: "2.3.0"})}
	twoLastUnsorted := []Range{rng("SEMVER", Event{LastAffected: "2.3.0"}, Event{Introduced: "2.0.0"}, Event{LastAffected: "1.5.0"}, Event{Introduced: "1.0.0"})}
	cases := []struct {
		name    string
		version string
		rec     Record
		want    Match
	}{
		{"exact version list", "2.25.0", Record{Ecosystem: "PyPI", Versions: []string{"2.25.0"}}, Match{Affected: true}},
		{"version list miss", "2.25.1", Record{Ecosystem: "PyPI", Versions: []string{"2.25.0"}}, Match{}},
		{"pypi ranges only is unevaluated", "2.25.1", Record{Ecosystem: "PyPI", Ranges: []Range{rng("ECOSYSTEM", Event{Introduced: "0"})}}, Match{Unevaluated: UnevaluatedNoVersions}},
		{"pypi ranges with version list miss is evaluated", "2.25.1", Record{Ecosystem: "PyPI", Versions: []string{"2.25.0"}, Ranges: []Range{rng("ECOSYSTEM", Event{Introduced: "0"})}}, Match{}},
		{"pypi git range only is not unevaluated", "2.25.1", Record{Ecosystem: "PyPI", Ranges: []Range{rng("GIT", Event{Introduced: "deadbeef"})}}, Match{}},
		{"debian ranges only is unevaluated", "1.2-3", Record{Ecosystem: "Debian:12", Ranges: []Range{rng("ECOSYSTEM", Event{Introduced: "0"}, Event{Fixed: "1.2-4"})}}, Match{Unevaluated: UnevaluatedNoVersions}},
		{"semver intro/fixed inside", "4.17.20", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Introduced: "0"}, Event{Fixed: "4.17.21"})}}, Match{Affected: true}},
		{"semver at fixed", "4.17.21", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Introduced: "0"}, Event{Fixed: "4.17.21"})}}, Match{}},
		{"semver below introduced", "1.0.0", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Introduced: "2.0.0"}, Event{Fixed: "2.1.0"})}}, Match{}},
		{"npm ECOSYSTEM range is semver", "4.17.20", Record{Ecosystem: "npm", Ranges: []Range{rng("ECOSYSTEM", Event{Introduced: "3.7.0"}, Event{Fixed: "4.17.19"})}}, Match{}},
		{"two intervals, in second", "2.1.0", Record{Ecosystem: "npm", Ranges: two}, Match{Affected: true}},
		{"two intervals, between", "1.7.0", Record{Ecosystem: "npm", Ranges: two}, Match{}},
		{"two intervals unsorted, in second", "2.1.0", Record{Ecosystem: "npm", Ranges: twoUnsorted}, Match{Affected: true}},
		{"two intervals unsorted, in first", "1.2.0", Record{Ecosystem: "npm", Ranges: twoUnsorted}, Match{Affected: true}},
		{"two intervals unsorted, between", "1.7.0", Record{Ecosystem: "npm", Ranges: twoUnsorted}, Match{}},
		{"two intervals unsorted, after", "2.3.0", Record{Ecosystem: "npm", Ranges: twoUnsorted}, Match{}},
		{"unsorted introduced 0 last", "0.5.0", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Fixed: "1.0.0"}, Event{Introduced: "0"})}}, Match{Affected: true}},
		{"last_affected inclusive", "1.2.0", Record{Ecosystem: "Go", Ranges: []Range{rng("SEMVER", Event{Introduced: "0"}, Event{LastAffected: "1.2.0"})}}, Match{Affected: true}},
		{"last_affected exceeded", "1.2.1", Record{Ecosystem: "Go", Ranges: []Range{rng("SEMVER", Event{Introduced: "0"}, Event{LastAffected: "1.2.0"})}}, Match{}},
		{"two last_affected intervals, at second end", "2.3.0", Record{Ecosystem: "npm", Ranges: twoLast}, Match{Affected: true}},
		{"two last_affected intervals, between", "1.5.1", Record{Ecosystem: "npm", Ranges: twoLast}, Match{}},
		{"two last_affected intervals, after", "2.3.1", Record{Ecosystem: "npm", Ranges: twoLast}, Match{}},
		{"two last_affected unsorted, in first", "1.5.0", Record{Ecosystem: "npm", Ranges: twoLastUnsorted}, Match{Affected: true}},
		{"two last_affected unsorted, in second", "2.0.0", Record{Ecosystem: "npm", Ranges: twoLastUnsorted}, Match{Affected: true}},
		{"two last_affected unsorted, between", "1.9.0", Record{Ecosystem: "npm", Ranges: twoLastUnsorted}, Match{}},
		{"go v prefix", "v0.3.0", Record{Ecosystem: "Go", Ranges: []Range{rng("SEMVER", Event{Introduced: "0"}, Event{Fixed: "v0.3.3"})}}, Match{Affected: true}},
		{"prerelease ordering", "1.0.0-beta", Record{Ecosystem: "crates.io", Ranges: []Range{rng("SEMVER", Event{Introduced: "1.0.0"})}}, Match{}},
		{"git range ignored", "1.0.0", Record{Ecosystem: "npm", Ranges: []Range{rng("GIT", Event{Introduced: "deadbeef"})}}, Match{}},
		{"unparsable version", "git+ssh://x", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Introduced: "0"})}}, Match{Unparsed: true}},
		{"unparsable boundary dropped, still affected", "1.0.0", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Introduced: "0"}, Event{Fixed: "not-a-version"})}}, Match{Affected: true}},
		{"unparsable boundary dropped, uncertain miss", "1.0.0", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Introduced: "not-a-version"}, Event{Fixed: "2.0.0"})}}, Match{Unevaluated: UnevaluatedBadBoundary}},
		{"unparsable boundary in one range, hit in another", "1.0.0", Record{Ecosystem: "npm", Ranges: []Range{rng("SEMVER", Event{Introduced: "not-a-version"}), rng("SEMVER", Event{Introduced: "0"})}}, Match{Affected: true}},
		{"introduced only, open ended", "99.0.0", Record{Ecosystem: "Packagist", Ranges: []Range{rng("ECOSYSTEM", Event{Introduced: "1.0.0"})}}, Match{Affected: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Affects(tc.version, &tc.rec); got != tc.want {
				t.Fatalf("Affects(%q) = %+v want %+v", tc.version, got, tc.want)
			}
		})
	}
}

// Ranges the offline matcher cannot evaluate are never a silent pass: they
// are aggregated per ecosystem into sca.range-unevaluated and the run is
// reported partial, while evaluable records still match.
func TestOfflineRangeUnevaluated(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	mk := func(id, eco, name string, versions []string) *Vuln {
		var v Vuln
		aff := map[string]any{
			"package": map[string]string{"ecosystem": eco, "name": name},
			"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "9.9.9"}}}},
		}
		if versions != nil {
			aff["versions"] = versions
		}
		raw, _ := json.Marshal(map[string]any{"id": id, "summary": "x", "affected": []map[string]any{aff}})
		json.Unmarshal(raw, &v)
		return &v
	}
	stageVulns(t, st, "PyPI", mk("PYSEC-0001", "PyPI", "ranged", nil), mk("PYSEC-0002", "PyPI", "ranged", nil), mk("PYSEC-0003", "PyPI", "listed", []string{"1.0.0"}))
	e, _ := New(nil)
	e.Offline = &OfflineClient{Store: st}
	pkgs := []Package{
		{Ecosystem: "PyPI", Name: "ranged", Version: "1.0.0", File: "requirements.txt"},
		{Ecosystem: "PyPI", Name: "listed", Version: "1.0.0", File: "requirements.txt"},
		{Ecosystem: "PyPI", Name: "absent", Version: "1.0.0", File: "requirements.txt"},
	}
	var out []domain.Finding
	err := e.Lookup(context.Background(), pkgs, "repo:x", Name, engine.Options{}, func(f domain.Finding) error { out = append(out, f); return nil })
	var partial *engine.PartialError
	if !errors.As(err, &partial) || !strings.Contains(partial.Reason, "2 advisory range(s)") {
		t.Fatalf("want PartialError for 2 unevaluated ranges, got %v", err)
	}
	var unevaluated, vuln int
	for _, f := range out {
		switch {
		case f.RuleID == RuleRangeUnevaluated:
			unevaluated++
			ev := f.Evidence[0].Redacted
			if f.Severity != domain.Info || !strings.Contains(ev, "2 PyPI advisory range(s)") || !strings.Contains(ev, "ranged@1.0.0 (PYSEC-0001)") || !strings.Contains(ev, "ranged@1.0.0 (PYSEC-0002)") || strings.Contains(ev, "listed@") {
				t.Fatalf("unevaluated finding: %+v", f)
			}
		case strings.HasPrefix(f.RuleID, "sca.osv."):
			vuln++
			if !strings.Contains(f.RuleID, "PYSEC-0003@") {
				t.Fatalf("only the listed version should match: %s", f.RuleID)
			}
		}
	}
	if unevaluated != 1 || vuln != 1 {
		t.Fatalf("unevaluated=%d vuln=%d: %+v", unevaluated, vuln, out)
	}

	// Through the engine Runner the status is partial, not ok and not failed.
	st2, _ := store.Open(":memory:")
	defer st2.Close()
	stageVulns(t, st2, "npm", mk("GHSA-aaaa-bbbb-cccc", "npm", "lodash", nil))
	e2, _ := New(nil)
	e2.Offline = &OfflineClient{Store: st2}
	dir := fixtureRepo(t)
	runErr := e2.Run(context.Background(), domain.Target{Type: domain.TargetPath, Value: dir}, engine.Options{}, func(domain.Finding) error { return nil })
	if runErr != nil {
		t.Fatalf("semver ecosystem evaluates ranges fully: %v", runErr)
	}
}
func TestDecodeRecordStrict(t *testing.T) {
	good := `{"id":"GHSA-aaaa-bbbb-cccc","aliases":["CVE-2020-1234"],"ecosystem":"npm","name":"x","versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}],"summary":"s","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}],"refs":["https://example.com/a"],"cwe":["CWE-79"],"modified":"2024-01-01T00:00:00Z"}`
	r, err := DecodeRecord([]byte(good))
	if err != nil || r.Name != "x" {
		t.Fatalf("good record: %v", err)
	}
	bad := map[string]string{
		"unknown field":     `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","extra":1}`,
		"trailing data":     good + ` {}`,
		"empty":             ``,
		"bad id":            `{"id":"../x","ecosystem":"npm","name":"x"}`,
		"missing name":      `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm"}`,
		"control in name":   `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"a\nb"}`,
		"bad range type":    `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","ranges":[{"type":"PEP440","events":[]}]}`,
		"two-field event":   `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","ranges":[{"type":"SEMVER","events":[{"introduced":"0","fixed":"1"}]}]}`,
		"empty event":       `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","ranges":[{"type":"SEMVER","events":[{}]}]}`,
		"bad ref scheme":    `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","refs":["javascript:alert(1)"]}`,
		"bad cwe":           `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","cwe":["79"]}`,
		"too many refs":     `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","refs":[` + strings.Repeat(`"https://e.com/",`, 10) + `"https://e.com/"]}`,
		"array not object":  `[1,2]`,
		"wrong field type":  `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","versions":"1.0.0"}`,
		"summary too long":  `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","summary":"` + strings.Repeat("a", 2000) + `"}`,
		"modified with ctl": `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","modified":"a\u0001"}`,
	}
	for name, line := range bad {
		if _, err := DecodeRecord([]byte(line)); err == nil {
			t.Errorf("%s: accepted %s", name, line)
		}
	}
	if _, err := DecodeRecord([]byte(`{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"` + strings.Repeat("a", MaxRecordBytes) + `"}`)); err == nil {
		t.Error("over-size record accepted")
	}
}

// FuzzBundleRecord: the strict decoder never panics, and every accepted
// record survives a marshal/decode round trip unchanged (so what the loader
// stores is exactly what the matcher reads back).
func FuzzBundleRecord(f *testing.F) {
	seeds := []string{
		`{"id":"GHSA-aaaa-bbbb-cccc","aliases":["CVE-2020-1234"],"ecosystem":"npm","name":"x","versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}],"summary":"s","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}],"refs":["https://example.com/a"],"cwe":["CWE-79"],"modified":"2024-01-01T00:00:00Z"}`,
		`{"id":"GO-2024-0001","ecosystem":"Go","name":"example.com/m","ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"v1.2.3"}]}]}`,
		`{"id":"PYSEC-2021-1","ecosystem":"PyPI","name":"requests","versions":["2.25.0","2.25.1"]}`,
		`{"id":"x","ecosystem":"","name":""}`, `[]`, `null`, `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"npm","name":"x","evil":true}`, "",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		r, err := DecodeRecord(line)
		if err != nil {
			return
		}
		r.Clean(nil)
		again, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal accepted record: %v", err)
		}
		r2, err := DecodeRecord(again)
		if err != nil {
			t.Fatalf("round trip rejected: %v\n%s", err, again)
		}
		if r2.ID != r.ID || r2.Ecosystem != r.Ecosystem || r2.Name != r.Name || len(r2.Ranges) != len(r.Ranges) || len(r2.Versions) != len(r.Versions) {
			t.Fatalf("round trip changed the record:\n%+v\n%+v", r, r2)
		}
		for _, ver := range []string{"1.0.0", "v0.0.0-20200101000000-abcdef", "git+ssh://x", ""} {
			_ = Affects(ver, &r) // must not panic
		}
		_ = r.ToVuln()
		_ = r.Row()
	})
}
