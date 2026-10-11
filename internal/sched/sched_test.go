package sched_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/sched"
	"github.com/iamstoick/scnr/internal/store"
	"github.com/iamstoick/scnr/internal/wizard"
)

// fakeStore is an in-memory sched.ScheduleStore.
type fakeStore struct {
	mu    sync.Mutex
	rows  map[string]store.Schedule
	marks []markCall
}

type markCall struct {
	name, scanID, status string
	at, next             time.Time
}

func (f *fakeStore) ListSchedules(context.Context) ([]store.Schedule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Schedule
	for _, s := range f.rows {
		out = append(out, s)
	}
	return out, nil
}

func (f *fakeStore) MarkScheduleRun(_ context.Context, name string, at time.Time, scanID, status string, next time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marks = append(f.marks, markCall{name, scanID, status, at, next})
	if s, ok := f.rows[name]; ok {
		s.LastRun = &at
		s.LastScanID = scanID
		s.LastStatus = status
		s.NextRun = next
		f.rows[name] = s
	}
	return nil
}

func testAudit(t *testing.T) (*audit.Writer, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	w, err := audit.New(s, "")
	if err != nil {
		t.Fatal(err)
	}
	return w, s
}

func auditActions(t *testing.T, s *store.Store) []store.AuditEntry {
	t.Helper()
	rows, err := s.ListAudit(context.Background(), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a", "weekly", "team-a-1", strings.Repeat("x", 64)} {
		if err := sched.ValidName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "A", "a b", "a/b", "-a", "a_", strings.Repeat("x", 65)} {
		if err := sched.ValidName(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestParseCron(t *testing.T) {
	for _, ok := range []string{"@hourly", "@daily", "@weekly", "@monthly", "0 * * * *", "0 2 * * 1", "15 3 1 * *", "0 0,12 * * *", "  @daily  "} {
		if _, err := sched.ParseCron(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "* * * * *", "*/30 * * * *", "0,30 * * * *", // too frequent
		"@every 2h", "@minutely", "@hourly extra", // unlisted descriptors
		"not a cron", "0 0 30 2 *", // invalid / never fires
	} {
		if _, err := sched.ParseCron(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// A second locker on the same file gets *LockedError carrying the pid;
// releasing lets another locker in. (C1.)
func TestLockSingleInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")
	release, err := sched.SystemLocker.TryLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	_, err = sched.SystemLocker.TryLock(path)
	var locked *sched.LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("second lock: %v, want *LockedError", err)
	}
	if locked.PID != os.Getpid() {
		t.Fatalf("pid = %d, want %d", locked.PID, os.Getpid())
	}
	running, pid := sched.LockState(filepath.Dir(path))
	if !running || pid != os.Getpid() {
		t.Fatalf("LockState = %v/%d", running, pid)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if running, _ := sched.LockState(filepath.Dir(path)); running {
		t.Fatal("LockState still running after release")
	}
	release2, err := sched.SystemLocker.TryLock(path)
	if err != nil {
		t.Fatalf("re-lock: %v", err)
	}
	_ = release2()
	if running, _ := sched.LockState(t.TempDir()); running {
		t.Fatal("LockState on missing file reports running")
	}
}

// A schedule 3 weeks past due runs exactly once; the backlog collapses
// into one audited overlap skip and next_run advances from now. (C4.)
func TestDaemonCatchUpOnce(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	fs := &fakeStore{rows: map[string]store.Schedule{
		"old": {Name: "old", Cron: "@hourly", Args: []string{"scan", "."}, Enabled: true, NextRun: now.Add(-3 * 7 * 24 * time.Hour)},
	}}
	w, s := testAudit(t)
	var calls int
	d := &sched.Daemon{
		Store: fs, Audit: w,
		Parse: func(args []string) (wizard.ScanRequest, error) {
			return wizard.ScanRequest{Targets: []string{"."}}, nil
		},
		Scan: func(context.Context, wizard.ScanRequest) (sched.RunOutcome, error) {
			calls++
			return sched.RunOutcome{ScanID: "s1", Status: "ok"}, nil
		},
		Lock: sched.SystemLocker, Home: t.TempDir(),
		Now: func() time.Time { return now }, Once: true,
	}
	if err := d.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("runs = %d, want 1", calls)
	}
	if len(fs.marks) != 1 || fs.marks[0].status != "ok" || fs.marks[0].scanID != "s1" {
		t.Fatalf("marks = %+v", fs.marks)
	}
	if next := fs.marks[0].next; !next.After(now) || next.After(now.Add(2*time.Hour)) {
		t.Fatalf("next = %v", next)
	}
	skips := 0
	for _, e := range auditActions(t, s) {
		if e.Action == audit.ActionScheduleSkipped {
			skips++
			var detail map[string]any
			if err := json.Unmarshal(e.Detail, &detail); err != nil || detail["reason"] != "overlap" {
				t.Fatalf("skip detail = %s", e.Detail)
			}
		}
	}
	if skips != 1 {
		t.Fatalf("overlap skips = %d, want 1", skips)
	}
}

// An hourly scan that runs 70 minutes overlaps its own next fire: one
// run, one audited skip, next_run on the following hour. (C4.)
func TestDaemonOverlapSkipped(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fs := &fakeStore{rows: map[string]store.Schedule{
		"h": {Name: "h", Cron: "@hourly", Args: []string{"scan", "."}, Enabled: true, NextRun: now},
	}}
	w, s := testAudit(t)
	var calls int
	d := &sched.Daemon{
		Store: fs, Audit: w,
		Parse: func(args []string) (wizard.ScanRequest, error) { return wizard.ScanRequest{}, nil },
		Scan: func(context.Context, wizard.ScanRequest) (sched.RunOutcome, error) {
			calls++
			now = now.Add(70 * time.Minute) // the run overruns its hour
			return sched.RunOutcome{ScanID: "s1", Status: "ok"}, nil
		},
		Lock: sched.SystemLocker, Home: t.TempDir(),
		Now: func() time.Time { return now }, Once: true,
	}
	if err := d.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("runs = %d, want 1", calls)
	}
	if want := time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC); !fs.marks[0].next.Equal(want) {
		t.Fatalf("next = %v, want %v", fs.marks[0].next, want)
	}
	found := false
	for _, e := range auditActions(t, s) {
		if e.Action == audit.ActionScheduleSkipped && strings.Contains(string(e.Detail), "overlap") {
			found = true
		}
	}
	if !found {
		t.Fatal("no overlap skip audited")
	}
}

// Unparseable stored argv (or cron) is refused at run time: no scan,
// next_run still advances, and the skip is audited. (C3.)
func TestDaemonSkipsBadRows(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fs := &fakeStore{rows: map[string]store.Schedule{
		"badargs": {Name: "badargs", Cron: "@hourly", Args: []string{"scan", ".", "--ack-authorized"}, Enabled: true, NextRun: now},
		"badcron": {Name: "badcron", Cron: "* * * * *", Args: []string{"scan", "."}, Enabled: true, NextRun: now},
	}}
	w, s := testAudit(t)
	d := &sched.Daemon{
		Store: fs, Audit: w,
		Parse: func(args []string) (wizard.ScanRequest, error) {
			return wizard.ScanRequest{}, errors.New("schedules refuse --ack-authorized")
		},
		Scan: func(context.Context, wizard.ScanRequest) (sched.RunOutcome, error) {
			t.Error("Scan called for a bad row")
			return sched.RunOutcome{}, nil
		},
		Lock: sched.SystemLocker, Home: t.TempDir(),
		Now: func() time.Time { return now }, Once: true,
	}
	if err := d.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fs.marks) != 2 {
		t.Fatalf("marks = %+v", fs.marks)
	}
	for _, m := range fs.marks {
		if !strings.HasPrefix(m.status, "skipped:") || !m.next.After(now) {
			t.Fatalf("mark %+v advances nothing", m)
		}
	}
	reasons := map[string]bool{}
	for _, e := range auditActions(t, s) {
		if e.Action == audit.ActionScheduleSkipped {
			var detail map[string]any
			_ = json.Unmarshal(e.Detail, &detail)
			reasons[fmt.Sprint(detail["reason"])] = true
		}
	}
	if !reasons["bad-args"] || !reasons["bad-cron"] {
		t.Fatalf("reasons = %v", reasons)
	}
}

// A failing run is recorded and the loop serves the next due schedule;
// one bad row never stalls the rest.
func TestDaemonContinuesAfterFailure(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(name string) store.Schedule {
		return store.Schedule{Name: name, Cron: "@hourly", Args: []string{"scan", "."}, Enabled: true, NextRun: now}
	}
	fs := &fakeStore{rows: map[string]store.Schedule{"a": mk("a"), "b": mk("b")}}
	w, _ := testAudit(t)
	var ran []string
	d := &sched.Daemon{
		Store: fs, Audit: w,
		Parse: func(args []string) (wizard.ScanRequest, error) { return wizard.ScanRequest{}, nil },
		Scan: func(_ context.Context, req wizard.ScanRequest) (sched.RunOutcome, error) {
			ran = append(ran, req.Schedule)
			if req.Schedule == "a" {
				return sched.RunOutcome{}, errors.New("boom")
			}
			return sched.RunOutcome{ScanID: "sb", Status: "ok"}, nil
		},
		Lock: sched.SystemLocker, Home: t.TempDir(),
		Now: func() time.Time { return now }, Once: true,
	}
	if err := d.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 2 {
		t.Fatalf("ran = %v", ran)
	}
	got := map[string]string{}
	for _, m := range fs.marks {
		got[m.name] = m.status
	}
	if !strings.HasPrefix(got["a"], "failed:") || got["b"] != "ok" {
		t.Fatalf("statuses = %v", got)
	}
}

func TestNewNotifierValidation(t *testing.T) {
	for _, ok := range []string{
		"https://relay.internal/scnr", "https://relay.internal:8443/h?x=1",
		"http://localhost:8080/hook", "http://127.0.0.1/hook", "http://[::1]:8080/hook",
	} {
		if _, err := sched.NewNotifier(ok, nil); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "ftp://x/h", "http://example.com/h", "http://10.0.0.1/h",
		"https://user@example.com/h", "https://", "not a url",
	} {
		if _, err := sched.NewNotifier(bad, nil); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// Webhook URLs often carry a token in path or query; request errors must
// never carry it into logs or audit rows.
func TestNotifyErrorHidesURL(t *testing.T) {
	// Closed loopback port, token in the URL: any failure must name the
	// failure without the URL.
	n, err := sched.NewNotifier("http://127.0.0.1:1/h?token=hunter2-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	n.Attempts = 1
	n.Backoff = func(int) time.Duration { return 0 }
	if err := n.Send(context.Background(), sched.Summary{Schedule: "s", ScanID: "id"}); err == nil {
		t.Fatal("Send to a closed port succeeded")
	} else if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "token=") {
		t.Fatalf("error leaks URL: %v", err)
	}
}

// The notify body carries counts and metadata only — this golden pins the
// exact keys so findings can never slip into the payload.
func TestNotifyBodySchema(t *testing.T) {
	var got []byte
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		got = body
	}))
	defer srv.Close()
	n, err := sched.NewNotifier(srv.URL+"/hook?token=hunter2", nil)
	if err != nil {
		t.Fatal(err)
	}
	n.Attempts = 1
	sum := sched.Summary{
		Schedule: "weekly", ScanID: "abc", StartedAt: "2026-01-01T00:00:00Z", FinishedAt: "2026-01-01T00:01:00Z",
		Profile: "standard", Targets: []string{"10.0.0.0/24"}, Score: 80, Grade: "B",
		Counts: map[string]int{"high": 1, "medium": 2}, Partial: true, ExitCode: 0,
		ReportPaths: []string{"/out/abc/report.html"},
	}
	if err := n.Send(context.Background(), sum); err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":"1","schedule":"weekly","scan_id":"abc","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:01:00Z","profile":"standard","targets":["10.0.0.0/24"],"score":80,"grade":"B","counts":{"high":1,"medium":2},"partial":true,"exit_code":0,"report_paths":["/out/abc/report.html"]}`
	if string(got) != want {
		t.Fatalf("body:\n got %s\nwant %s", got, want)
	}
	if contentType != "application/json" {
		t.Fatalf("content-type = %q", contentType)
	}
}

// A redirecting webhook is never followed: the 3xx fails the send and
// the redirect target sees no request. (C5.)
func TestNotifyRedirectNotFollowed(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/landed", http.StatusFound)
	}))
	defer srv.Close()
	n, err := sched.NewNotifier(srv.URL+"/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	n.Attempts = 1
	if err := n.Send(context.Background(), sched.Summary{Schedule: "s"}); err == nil {
		t.Fatal("redirected send succeeded")
	}
	if hits != 0 {
		t.Fatalf("redirect target hit %d times", hits)
	}
}

// The notify client cannot reach metadata endpoints even when the URL
// names one: the endpoint policy denies before dialing. (C5.)
func TestNotifyBlocked(t *testing.T) {
	n, err := sched.NewNotifier("https://169.254.169.254/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	n.Attempts = 1
	n.Backoff = func(int) time.Duration { return 0 }
	err = n.Send(context.Background(), sched.Summary{Schedule: "s"})
	if err == nil || !strings.Contains(err.Error(), "E_SCOPE_DENIED") {
		t.Fatalf("metadata send: %v", err)
	}
}
