package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateUpDown(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	v, err := s.SchemaVersion(ctx)
	latest, _ := LatestMigrationVersion()
	if err != nil || v != latest || v < 1 {
		t.Fatalf("version %d latest %d err %v", v, latest, err)
	}
	if err := s.MigrateDown(ctx, 1, false); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.SchemaVersion(ctx); v != latest-1 {
		t.Fatalf("after down: %d", v)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.SchemaVersion(ctx); v != latest {
		t.Fatalf("after re-up: %d", v)
	}
}

func sampleScan() *domain.Scan {
	tg := domain.Target{Raw: "127.0.0.1", Type: domain.TargetHost, Value: "127.0.0.1", Hostname: "127.0.0.1"}
	return &domain.Scan{ID: domain.NewID(), StartedAt: time.Now(), Profile: "quick", Targets: []domain.Target{tg},
		TargetSetHash: domain.TargetSetHash([]domain.Target{tg}), ScopeHash: "sh", Consent: domain.ConsentRecord{Method: "private-range", By: "tester"}}
}

func TestScanFindingsRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	sc := sampleScan()
	if err := s.InsertScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	w := s.NewWriter(ctx, sc.ID, func(string) bool { return false })
	eps := 0.5
	for i := 0; i < 3; i++ {
		f := domain.Finding{AssetKey: "host:127.0.0.1", RuleID: "net.open-port", Engine: "netscan", Title: fmt.Sprintf("port %d", i),
			Severity: domain.Info, Confidence: domain.Confirmed, Location: fmt.Sprintf("127.0.0.1:%d", 80+i), Risk: 10 * i,
			CVEs: []string{"CVE-2020-0001"}, EPSS: &eps, KEV: i == 2, CVSS: &domain.CVSS{Vector: "V", Score: 5},
			Evidence: []domain.Evidence{{Kind: "banner", Location: "x", Redacted: "r", Hash: "h"}}}
		if err := w.Add(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Count() != 3 {
		t.Fatalf("count %d", w.Count())
	}
	sc.FinishedAt = time.Now()
	sc.Engines = []domain.EngineRun{{Name: "netscan", Status: "ok", Duration: 1500 * time.Millisecond}}
	sc.Posture = domain.PostureScore{Score: 97, Grade: "A"}
	if err := s.FinishScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScan(ctx, "latest")
	if err != nil || got.ID != sc.ID || got.Posture.Score != 97 || len(got.Targets) != 1 || len(got.Engines) != 1 || got.Engines[0].Duration != 1500*time.Millisecond {
		t.Fatalf("GetScan: %+v %v", got, err)
	}
	list, err := s.ListFindings(ctx, FindingFilter{ScanID: sc.ID})
	if err != nil || len(list) != 3 || list[0].Risk != 20 || list[0].AssetKey != "host:127.0.0.1" || !list[0].KEV || *list[0].EPSS != 0.5 || list[0].CVSS.Score != 5 {
		t.Fatalf("ListFindings: %+v %v", list, err)
	}
	one, err := s.GetFinding(ctx, list[0].Fingerprint)
	if err != nil || len(one.Evidence) != 1 || one.Evidence[0].Redacted != "r" {
		t.Fatalf("GetFinding: %+v %v", one, err)
	}
	sev := domain.Low
	if l, _ := s.ListFindings(ctx, FindingFilter{MinSeverity: &sev}); len(l) != 0 {
		t.Fatal("severity filter")
	}
	n, _ := s.CountFindings(ctx, sc.ID)
	if n != 3 {
		t.Fatalf("count %d", n)
	}
	// Iterator sees all with evidence.
	it := s.Iterate(sc.ID)
	seen := 0
	for {
		f, ok := it.Next(ctx)
		if !ok {
			break
		}
		seen++
		if len(f.Evidence) != 1 {
			t.Fatal("iterator evidence")
		}
	}
	if it.Err() != nil || seen != 3 {
		t.Fatalf("iterate: %d %v", seen, it.Err())
	}
	// Re-scan: same fingerprints upsert, occurrence recorded once per scan.
	sc2 := sampleScan()
	s.InsertScan(ctx, sc2)
	w2 := s.NewWriter(ctx, sc2.ID, nil)
	w2.Add(domain.Finding{AssetKey: "host:127.0.0.1", RuleID: "net.open-port", Engine: "netscan", Title: "port 0", Location: "127.0.0.1:80", Risk: 5})
	w2.Close()
	if l, _ := s.ListFindings(ctx, FindingFilter{}); len(l) != 3 {
		t.Fatalf("dedupe by fingerprint failed: %d", len(l))
	}
	if n, _ := s.CountFindings(ctx, sc2.ID); n != 1 {
		t.Fatalf("occurrences for scan2 = %d", n)
	}
	summaries, _ := s.ListScans(ctx, 10, 0)
	if len(summaries) != 2 || summaries[0].ID != sc2.ID {
		t.Fatalf("ListScans %+v", summaries)
	}
	prev, ok, _ := s.PreviousScanScore(ctx, sc2.TargetSetHash, sc2.ID)
	if !ok || prev != 97 {
		t.Fatalf("previous score %d %v", prev, ok)
	}
	assets, _ := s.ListAssets(ctx, 10, 0)
	if len(assets) != 1 || assets[0].Key != "host:127.0.0.1" {
		t.Fatalf("assets %+v", assets)
	}
}

func TestAuditAppendOnly(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, err := s.AppendAudit(ctx, AuditEntry{Actor: "u", Action: "scan", ScanID: "abc", Detail: []byte(`{"x":1}`)})
	if err != nil || id == 0 {
		t.Fatal(err)
	}
	rows, _ := s.ListAudit(ctx, "abc", 10)
	if len(rows) != 1 || string(rows[0].Detail) != `{"x":1}` {
		t.Fatalf("%+v", rows)
	}
	// Static guarantee: no UPDATE/DELETE against audit_log in this package
	// (every non-test source file, so new query files are covered too).
	srcs, _ := filepath.Glob("*.go")
	for _, p := range srcs {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(p)
		for _, stmt := range []string{"UPDATE audit_log", "DELETE FROM audit_log"} {
			if strings.Contains(string(src), stmt) {
				t.Fatalf("%s contains %q", p, stmt)
			}
		}
	}
	// Database guarantee (migration 0002): triggers abort UPDATE and DELETE.
	if _, err := s.db.ExecContext(ctx, `UPDATE audit_log SET detail = '{}' WHERE id = ?`, id); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("UPDATE on audit_log must abort, got %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE id = ?`, id); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("DELETE on audit_log must abort, got %v", err)
	}
	rows, _ = s.ListAudit(ctx, "abc", 10)
	if len(rows) != 1 || string(rows[0].Detail) != `{"x":1}` {
		t.Fatalf("row changed: %+v", rows)
	}
	// Rolling back while audit rows exist is refused unless explicitly accepted.
	if err := s.MigrateDown(ctx, 1, false); !errors.Is(err, ErrAuditLoss) {
		t.Fatalf("MigrateDown with audit rows: want ErrAuditLoss, got %v", err)
	}
	if n, _ := s.AuditRowCount(ctx); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	if err := s.MigrateDown(ctx, 1, true); err != nil {
		t.Fatalf("acknowledged rollback: %v", err)
	}
}

func TestVerificationsAndVulnDB(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.PutVerification(ctx, Verification{Host: "Example.test", Method: "dns-txt", VerifiedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetVerification(ctx, "example.test")
	if err != nil || v.Method != "dns-txt" {
		t.Fatal(err)
	}
	if _, err := s.GetVerification(ctx, "nope"); err != ErrNotFound {
		t.Fatal("want ErrNotFound")
	}
	if err := s.ReplaceKEV(ctx, []KEVEntry{{CVE: "CVE-2021-44228", Added: "2021-12-10"}}, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceEPSS(ctx, []EPSSEntry{{CVE: "CVE-2021-44228", Score: 0.97, Percentile: 0.99}}, "v1"); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.LookupKEV(ctx, "cve-2021-44228"); !k {
		t.Fatal("kev lookup case-insensitive")
	}
	if sc, ok, _ := s.LookupEPSS(ctx, "CVE-2021-44228"); !ok || sc != 0.97 {
		t.Fatal("epss")
	}
	metas, _ := s.VulnDBStatus(ctx)
	if len(metas) != 3 || metas[0].Rows != 1 || metas[0].UpdatedAt.IsZero() || metas[2].Source != SourceOSVOffline || metas[2].Rows != 0 {
		t.Fatalf("%+v", metas)
	}
	if err := s.VulnCachePut(ctx, "GHSA-x", []byte(`{"id":"GHSA-x"}`)); err != nil {
		t.Fatal(err)
	}
	if b, ok, _ := s.VulnCacheGet(ctx, "GHSA-x", time.Hour); !ok || string(b) != `{"id":"GHSA-x"}` {
		t.Fatal("cache get")
	}
	if _, ok, _ := s.VulnCacheGet(ctx, "GHSA-x", -time.Second); ok {
		t.Fatal("stale cache returned")
	}
}

// TestWriterStreams50kFindings is acceptance criterion 10: 50 000 synthetic
// findings must not accumulate in memory (RSS < 300 MiB).
func TestWriterStreams50kFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	s := openTest(t)
	ctx := context.Background()
	sc := sampleScan()
	s.InsertScan(ctx, sc)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	w := s.NewWriter(ctx, sc.ID, nil)
	const n = 50000
	var peak uint64
	for i := 0; i < n; i++ {
		f := domain.Finding{AssetKey: fmt.Sprintf("host:10.0.%d.%d", i/250%256, i%250+1), RuleID: "net.open-port", Engine: "fake",
			Title: "synthetic", Location: fmt.Sprintf("10.0.0.1:%d", i), Risk: i % 100, Severity: domain.Info,
			Evidence: []domain.Evidence{{Kind: "banner", Location: "l", Redacted: strings.Repeat("x", 200), Hash: "h"}}}
		if err := w.Add(f); err != nil {
			t.Fatal(err)
		}
		if i%10000 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.Sys > peak {
				peak = m.Sys
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.Sys > peak {
		peak = after.Sys
	}
	t.Logf("50k findings: Sys before %d MiB, peak %d MiB, HeapInuse %d MiB", before.Sys>>20, peak>>20, after.HeapInuse>>20)
	if peak > 300<<20 {
		t.Fatalf("RSS proxy (MemStats.Sys) %d MiB exceeds 300 MiB", peak>>20)
	}
	if w.Count() != n {
		t.Fatalf("count %d", w.Count())
	}
	cnt, _ := s.CountFindings(ctx, sc.ID)
	if cnt != n {
		t.Fatalf("occurrences %d", cnt)
	}
	// Iterator pages without loading everything.
	it := s.Iterate(sc.ID)
	seen := 0
	for {
		if _, ok := it.Next(ctx); !ok {
			break
		}
		seen++
	}
	if seen != n || it.Err() != nil {
		t.Fatalf("iterated %d %v", seen, it.Err())
	}
}

// Phase 4a: an offline load is all-or-nothing and replaces, never merges.
func TestOfflineLoadStagesAndRollsBack(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	rec := func(id, name string) AffectedRecord {
		return AffectedRecord{ID: id, Ecosystem: "npm", Name: name, Body: []byte(`{"id":"` + id + `","ecosystem":"npm","name":"` + name + `"}`)}
	}
	l, err := s.BeginOfflineLoad(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Stage(ctx, rec("GHSA-1", "a")); err != nil {
		t.Fatal(err)
	}
	if err := l.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.OSVAffectedCount(ctx); n != 0 {
		t.Fatalf("rollback left %d rows", n)
	}
	if err := l.Stage(ctx, rec("GHSA-1", "a")); !errors.Is(err, ErrLoadFinished) {
		t.Fatalf("stage after rollback: %v", err)
	}

	l, _ = s.BeginOfflineLoad(ctx)
	for _, r := range []AffectedRecord{rec("GHSA-1", "a"), rec("GHSA-2", "a"), rec("GHSA-1", "b"), {ID: "", Ecosystem: "npm", Name: "x"}} {
		err := l.Stage(ctx, r)
		if r.ID == "" && err == nil {
			t.Fatal("record without id accepted")
		}
	}
	if err := l.Commit(ctx, "v1"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.OSVAffectedCount(ctx); n != 3 || l.Rows() != 3 {
		t.Fatalf("rows %d staged %d", n, l.Rows())
	}
	rows, err := s.AffectedFor(ctx, "npm", "a")
	if err != nil || len(rows) != 2 || rows[0].ID != "GHSA-1" || rows[0].VersionsJSON != "[]" || string(rows[0].Body) == "" {
		t.Fatalf("AffectedFor: %+v %v", rows, err)
	}
	byID, err := s.AffectedByIDs(ctx, []string{"GHSA-1", "nope"})
	if err != nil || len(byID) != 2 {
		t.Fatalf("AffectedByIDs: %+v %v", byID, err)
	}
	metas, _ := s.VulnDBStatus(ctx)
	if metas[2].Source != SourceOSVOffline || metas[2].Rows != 3 || metas[2].Version != "v1" {
		t.Fatalf("%+v", metas[2])
	}

	// A second load replaces the first entirely.
	l, _ = s.BeginOfflineLoad(ctx)
	l.Stage(ctx, rec("GHSA-9", "z"))
	if err := l.Commit(ctx, "v2"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.OSVAffectedCount(ctx); n != 1 {
		t.Fatalf("replace: %d rows", n)
	}
	if err := l.Commit(ctx, "v3"); !errors.Is(err, ErrLoadFinished) {
		t.Fatalf("double commit: %v", err)
	}
	// Down migration removes the table and its meta row; up restores it empty.
	// Two steps: 0004 (schedules, unrelated) must fall before 0003 (osv offline).
	if err := s.MigrateDown(ctx, 2, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.OSVAffectedCount(ctx); n != 0 {
		t.Fatal("table survived down/up")
	}
	if metas, _ := s.VulnDBStatus(ctx); !metas[2].UpdatedAt.IsZero() {
		t.Fatal("meta row survived down migration")
	}
}

// TestScanIntrusiveMetaRoundTrip: scans.meta.intrusive records the active
// outcome ({targets, probes}), SetScanMetaValue updates the probe count
// after the run, and GetScan parses it back. Pre-4d rows without the key
// read back as Ran=false.
func TestScanIntrusiveMetaRoundTrip(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	sc := sampleScan()
	sc.Intrusive = domain.IntrusiveOutcome{Ran: true, Targets: []string{"http://127.0.0.1/"}, Probes: 0}
	if err := s.InsertScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if err := s.SetScanMetaValue(ctx, sc.ID, "intrusive", map[string]any{"targets": []string{"http://127.0.0.1/"}, "probes": 42}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Intrusive.Ran || len(got.Intrusive.Targets) != 1 || got.Intrusive.Probes != 42 {
		t.Fatalf("%+v", got.Intrusive)
	}
	if got.Schedule != "" {
		t.Fatalf("schedule leaked: %q", got.Schedule)
	}
	plain := sampleScan()
	if err := s.InsertScan(ctx, plain); err != nil {
		t.Fatal(err)
	}
	got2, err := s.GetScan(ctx, plain.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Intrusive.Ran {
		t.Fatalf("pre-4d row reads intrusive: %+v", got2.Intrusive)
	}
}
