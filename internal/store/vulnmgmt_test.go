package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
)

// runScan records a scan whose findings are the given rule IDs on one asset.
func runScan(t *testing.T, s *Store, rules ...string) *domain.Scan {
	t.Helper()
	ctx := context.Background()
	sc := sampleScan()
	if err := s.InsertScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	w := s.NewWriter(ctx, sc.ID, nil)
	for _, r := range rules {
		risk := 50
		if strings.HasPrefix(r, "high.") {
			risk = 80
		}
		if err := w.Add(domain.Finding{AssetKey: "host:127.0.0.1", RuleID: r, Engine: "t", Title: r, Severity: domain.High, Location: "127.0.0.1:1", Risk: risk}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sc.FinishedAt = time.Now()
	if err := s.FinishScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	return sc
}

func statusOf(t *testing.T, s *Store, rule string) domain.Status {
	t.Helper()
	f, err := s.GetFinding(context.Background(), domain.Fingerprint(rule, "host:127.0.0.1", "127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	return f.Status
}

// Acceptance 2.4: a finding absent from the second scan is marked fixed and
// the diff reports 1 fixed / 0 new.
func TestDiffAndMarkFixed(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	a := runScan(t, s, "x.a", "x.b", "x.c")
	time.Sleep(2 * time.Millisecond)
	b := runScan(t, s, "x.a", "x.b")
	prev, ok, err := s.PreviousScan(ctx, b.TargetSetHash, b.ID)
	if err != nil || !ok || prev != a.ID {
		t.Fatalf("previous %q %v %v", prev, ok, err)
	}
	n, err := s.MarkFixed(ctx, b.ID, []string{"t"})
	if err != nil || n != 1 {
		t.Fatalf("marked %d %v", n, err)
	}
	if statusOf(t, s, "x.c") != domain.StatusFixed || statusOf(t, s, "x.a") != domain.StatusOpen {
		t.Fatal("statuses")
	}
	d, err := s.DiffScans(ctx, a.ID, b.ID)
	if err != nil || len(d.Fixed) != 1 || len(d.New) != 0 || d.Unchanged != 2 {
		t.Fatalf("diff %+v %v", d, err)
	}
	// Reappearing finding is reopened by the writer.
	c := runScan(t, s, "x.a", "x.b", "x.c")
	if statusOf(t, s, "x.c") != domain.StatusOpen {
		t.Fatal("regressed finding not reopened")
	}
	d, _ = s.DiffScans(ctx, b.ID, c.ID)
	if len(d.New) != 1 || len(d.Fixed) != 0 {
		t.Fatalf("diff %+v", d)
	}
	if _, err := s.DiffScans(ctx, a.ID, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing scan: %v", err)
	}
}

// Finding 4: a later scan in which an engine did not run (skipped, failed,
// or not selected) must not mark that engine's findings fixed; a full
// successful rescan still does.
func TestMarkFixedOnlyForEnginesThatRan(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	netF := domain.Finding{AssetKey: "host:127.0.0.1", RuleID: "net.open-port", Engine: "netscan", Title: "a", Location: "127.0.0.1:22", Status: domain.StatusOpen}
	kevF := domain.Finding{AssetKey: "host:127.0.0.1", RuleID: "nuclei:CVE-2024-0001", Engine: "adapter:nuclei", Title: "b", Location: "http://127.0.0.1/x", Status: domain.StatusOpen, KEV: true, Severity: domain.Critical, Risk: 95}
	kevFP := domain.Fingerprint(kevF.RuleID, kevF.AssetKey, kevF.Location)
	record := func(findings ...domain.Finding) *domain.Scan {
		t.Helper()
		sc := sampleScan()
		if err := s.InsertScan(ctx, sc); err != nil {
			t.Fatal(err)
		}
		w := s.NewWriter(ctx, sc.ID, nil)
		for _, f := range findings {
			if err := w.Add(f); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		sc.FinishedAt = time.Now()
		if err := s.FinishScan(ctx, sc); err != nil {
			t.Fatal(err)
		}
		return sc
	}
	status := func() domain.Status {
		t.Helper()
		f, err := s.GetFinding(ctx, kevFP)
		if err != nil {
			t.Fatal(err)
		}
		return f.Status
	}
	record(netF, kevF)
	// Only netscan completed (nuclei skipped or --engines netscan): stays open.
	sc2 := record(netF)
	if n, err := s.MarkFixed(ctx, sc2.ID, []string{"netscan"}); err != nil || n != 0 || status() != domain.StatusOpen {
		t.Fatalf("marked %d err %v status %s; KEV finding must stay open when nuclei did not run", n, err, status())
	}
	// No engine completed at all: nothing is marked.
	if n, err := s.MarkFixed(ctx, sc2.ID, nil); err != nil || n != 0 || status() != domain.StatusOpen {
		t.Fatalf("marked %d err %v", n, err)
	}
	// Full successful rescan without the finding: fixed (acceptance 2.4 still
	// holds), even though the immediately preceding scan did not carry it.
	sc3 := record(netF)
	if n, err := s.MarkFixed(ctx, sc3.ID, []string{"netscan", "adapter:nuclei"}); err != nil || n != 1 || status() != domain.StatusFixed {
		t.Fatalf("marked %d err %v status %s", n, err, status())
	}
	// A different target set never vouches for this one's findings.
	other := &domain.Scan{ID: domain.NewID(), StartedAt: time.Now(), Profile: "quick", TargetSetHash: "other-set", ScopeHash: "sh",
		Targets: []domain.Target{{Raw: "10.9.9.9", Type: domain.TargetHost, Value: "10.9.9.9", Hostname: "10.9.9.9"}}, Consent: domain.ConsentRecord{Method: "private-range", By: "t"}}
	if err := s.InsertScan(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := s.NewWriter(ctx, other.ID, nil).Close(); err != nil {
		t.Fatal(err)
	}
	record(netF, kevF) // reopened by the writer
	if n, err := s.MarkFixed(ctx, other.ID, []string{"netscan", "adapter:nuclei"}); err != nil || n != 0 || status() != domain.StatusOpen {
		t.Fatalf("other target set marked %d err %v status %s", n, err, status())
	}
}

// Acceptance 2.5: accept needs reason and expiry; expired acceptances revert
// to open on the next scan and are reported for auditing.
func TestSuppressionsLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	runScan(t, s, "high.a", "x.b")
	fpA := domain.Fingerprint("high.a", "host:127.0.0.1", "127.0.0.1:1")
	now := time.Now()
	for _, bad := range []Suppression{
		{Fingerprint: fpA, ExpiresAt: now.Add(time.Hour)},                         // no reason
		{Fingerprint: fpA, Reason: "r"},                                           // no expiry
		{Fingerprint: fpA, Reason: "r", ExpiresAt: now.Add(-time.Hour)},           // past
		{Fingerprint: fpA, Reason: "r", ExpiresAt: now.Add(400 * 24 * time.Hour)}, // > 365d
		{Reason: "r", ExpiresAt: now.Add(time.Hour)},                              // no target
	} {
		if _, _, err := s.AddSuppression(ctx, bad); err == nil {
			t.Fatalf("accepted invalid suppression %+v", bad)
		}
	}
	sp, applied, err := s.AddSuppression(ctx, Suppression{Fingerprint: fpA, Reason: "known, mitigated by WAF", CreatedBy: "t", ExpiresAt: now.Add(time.Hour)})
	if err != nil || applied != 1 || sp.ID == "" {
		t.Fatalf("%v %d", err, applied)
	}
	if statusOf(t, s, "high.a") != domain.StatusAccepted {
		t.Fatal("not accepted")
	}
	// Re-scan: writer keeps accepted; active suppression still applies.
	runScan(t, s, "high.a", "x.b")
	if statusOf(t, s, "high.a") != domain.StatusAccepted {
		t.Fatal("accepted status lost on re-scan")
	}
	n, reverted, err := s.ApplySuppressions(ctx, "any", now)
	if err != nil || len(reverted) != 0 || n != 0 {
		t.Fatalf("apply %d %v %v", n, reverted, err)
	}
	// Expired: reverts to open and reports the suppression.
	n, reverted, err = s.ApplySuppressions(ctx, "any", now.Add(2*time.Hour))
	if err != nil || len(reverted) != 1 || reverted[0].Reopened != 1 || reverted[0].Suppression.ID != sp.ID {
		t.Fatalf("expiry: %d %+v %v", n, reverted, err)
	}
	if statusOf(t, s, "high.a") != domain.StatusOpen {
		t.Fatal("expired acceptance did not revert")
	}
	// Idempotent: a second pass reports nothing.
	if _, reverted, _ = s.ApplySuppressions(ctx, "any", now.Add(2*time.Hour)); len(reverted) != 0 {
		t.Fatal("expiry reported twice")
	}
	// Rule-level acceptance scoped to an asset, then revoke reopens.
	sp2, applied, err := s.AddSuppression(ctx, Suppression{RuleID: "x.b", AssetKey: "host:127.0.0.1", Reason: "r", ExpiresAt: now.Add(time.Hour)})
	if err != nil || applied != 1 {
		t.Fatal(err)
	}
	if _, applied, _ := s.AddSuppression(ctx, Suppression{RuleID: "x.b", AssetKey: "host:other", Reason: "r", ExpiresAt: now.Add(time.Hour)}); applied != 0 {
		t.Fatal("asset scope ignored")
	}
	list, _ := s.ListSuppressions(ctx, false, 10)
	if len(list) != 3 {
		t.Fatalf("list %d", len(list))
	}
	got, reopened, err := s.RevokeSuppression(ctx, sp2.ID[:12])
	if err != nil || reopened != 1 || got.RevokedAt.IsZero() {
		t.Fatalf("revoke %v %d", err, reopened)
	}
	if statusOf(t, s, "x.b") != domain.StatusOpen {
		t.Fatal("revoke did not reopen")
	}
	if _, _, err := s.RevokeSuppression(ctx, sp2.ID); err == nil {
		t.Fatal("double revoke accepted")
	}
	if _, err := s.GetSuppression(ctx, "zzzzzzzzzz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := s.GetSuppression(ctx, "abc"); err == nil {
		t.Fatal("short prefix accepted")
	}
	list, _ = s.ListSuppressions(ctx, true, 10)
	if len(list) != 3 || len(must(s.ListSuppressions(ctx, false, 10))) != 2 {
		t.Fatalf("list after revoke %d", len(list))
	}
}

func must(v []Suppression, err error) []Suppression { return v }

func TestBaselineAndRiskRows(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	sc := runScan(t, s, "high.a", "x.b", "x.c")
	fpA := domain.Fingerprint("high.a", "host:127.0.0.1", "127.0.0.1:1")
	sup, re, err := s.ApplyBaseline(ctx, sc.ID, []string{fpA}, []string{"x.c"})
	if err != nil || sup != 2 || re != 0 {
		t.Fatalf("baseline %d %d %v", sup, re, err)
	}
	if statusOf(t, s, "high.a") != domain.StatusSuppressed || statusOf(t, s, "x.c") != domain.StatusSuppressed || statusOf(t, s, "x.b") != domain.StatusOpen {
		t.Fatal("baseline statuses")
	}
	var open, suppressed int
	if err := s.ScanRiskRows(ctx, sc.ID, func(r RiskRow) {
		if r.Status == domain.StatusOpen {
			open++
		} else {
			suppressed++
		}
	}); err != nil || open != 1 || suppressed != 2 {
		t.Fatalf("rows open=%d sup=%d %v", open, suppressed, err)
	}
	// Scan again without a baseline: suppressed findings reopen.
	sc2 := runScan(t, s, "high.a", "x.b", "x.c")
	sup, re, err = s.ApplyBaseline(ctx, sc2.ID, nil, nil)
	if err != nil || sup != 0 || re != 2 {
		t.Fatalf("empty baseline %d %d %v", sup, re, err)
	}
	if statusOf(t, s, "high.a") != domain.StatusOpen {
		t.Fatal("not reopened")
	}
	fps, rules, err := s.ScanFingerprintsAndRules(ctx, sc2.ID)
	if err != nil || len(fps) != 3 || len(rules) != 3 {
		t.Fatalf("%d %d %v", len(fps), len(rules), err)
	}
	// Large IN lists are chunked.
	big := make([]string, 1200)
	for i := range big {
		big[i] = strings.Repeat("0", 63) + string(rune('a'+i%6))
	}
	if _, _, err := s.ApplyBaseline(ctx, sc2.ID, big, nil); err != nil {
		t.Fatal(err)
	}
}
