// Package sched runs scans on a schedule: stored schedules, a cron parser
// with a minimum interval, a single-instance daemon loop, and a notify
// webhook client that carries no findings. The daemon never prompts: every
// run is non-interactive, the scope file is re-read per run, and
// credentials are rebuilt per run. See SAFETY.md item 18.
//
// The daemon executes scans through Parse/Run hooks provided by the cli
// package (which owns the scan flagset and App): sched must not import cli
// or the two would form an import cycle.
package sched

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/store"
	"github.com/iamstoick/scnr/internal/wizard"
)

// nameRe validates schedule names.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ValidName reports whether name is a usable schedule name.
func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name %q must match ^[a-z0-9][a-z0-9-]{0,63}$", name)
	}
	return nil
}

// MinInterval is the smallest gap between two fires of one schedule:
// scanning is not a health check.
const MinInterval = time.Hour

// cronParser accepts standard 5-field expressions plus descriptors; the
// descriptor set is narrowed to the documented four below.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// allowedDescriptors are the only @-expressions schedules accept.
var allowedDescriptors = map[string]bool{"@hourly": true, "@daily": true, "@weekly": true, "@monthly": true}

// ParseCron parses expr and refuses schedules that would fire more often
// than MinInterval apart (measured at the next two fires).
func ParseCron(expr string) (cron.Schedule, error) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "@") {
		fields := strings.Fields(expr)
		if len(fields) != 1 || !allowedDescriptors[fields[0]] {
			return nil, fmt.Errorf("cron %q: only @hourly, @daily, @weekly and @monthly are accepted", expr)
		}
	}
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("cron %q: %w", expr, err)
	}
	now := time.Now()
	first := sched.Next(now)
	if first.IsZero() {
		return nil, fmt.Errorf("cron %q never fires", expr)
	}
	if second := sched.Next(first); second.Sub(first) < MinInterval {
		return nil, fmt.Errorf("cron %q fires more often than once an hour", expr)
	}
	return sched, nil
}

// ScheduleStore is the store subset the daemon needs. *store.Store
// implements it; tests use a fake.
type ScheduleStore interface {
	ListSchedules(ctx context.Context) ([]store.Schedule, error)
	MarkScheduleRun(ctx context.Context, name string, at time.Time, scanID, status string, next time.Time) error
}

// ParseFunc dry-parses stored argv into a scan request, applying the
// schedule forbidden list (no --ack-authorized, no secret-bearing flags,
// no unknown flags). Provided by cli; the daemon calls it before every
// run so hand-edited rows are re-validated (C3).
type ParseFunc func(args []string) (wizard.ScanRequest, error)

// RunOutcome is what one daemon run produced.
type RunOutcome struct {
	// ScanID is "" when no scan ran (refused, or failed before insert).
	ScanID string
	// Status is "ok", "partial: …", "failed: …", "refused: …",
	// "skipped: …", "timeout" or "interrupted".
	Status string
	// Summary is the notify payload; meaningful when ScanID != "".
	Summary Summary
}

// RunFunc executes one validated request non-interactively: reload the
// scope file (broken → skipped, audited), enforce the per-run timeout,
// run the scan. Provided by cli.
type RunFunc func(ctx context.Context, req wizard.ScanRequest) (RunOutcome, error)

// Summary is the notify webhook body: counts and metadata, never
// findings or evidence. See TestNotifyBodySchema for the pinned shape.
type Summary struct {
	SchemaVersion string         `json:"schema_version"`
	Schedule      string         `json:"schedule"`
	ScanID        string         `json:"scan_id"`
	StartedAt     string         `json:"started_at"`
	FinishedAt    string         `json:"finished_at"`
	Profile       string         `json:"profile"`
	Targets       []string       `json:"targets"`
	Score         int            `json:"score"`
	Grade         string         `json:"grade"`
	Counts        map[string]int `json:"counts"`
	Partial       bool           `json:"partial"`
	ExitCode      int            `json:"exit_code"`
	ReportPaths   []string       `json:"report_paths"`
}

// LockFileName is the daemon lock inside the scnr home directory.
const LockFileName = "daemon.lock"

// PollInterval caps how long the daemon sleeps without re-listing
// schedules, so externally added rows fire at most this late.
const PollInterval = time.Minute

// maxStatusBytes caps the last_status column; outcome errors can be long.
const maxStatusBytes = 500

// Daemon runs due schedules one at a time until ctx ends.
type Daemon struct {
	Store  ScheduleStore
	Audit  *audit.Writer
	Parse  ParseFunc
	Scan   RunFunc
	Lock   Locker
	Notify *Notifier // nil disables notifications
	Home   string
	// Out receives one line per served schedule; nil discards.
	Out io.Writer
	// Now is the clock (fake in tests); nil means time.Now.
	Now func() time.Time
	// Sleep waits until t or ctx ends (fake in tests); nil sleeps really.
	Sleep func(ctx context.Context, t time.Time) error
	// Once serves every currently-due schedule a single time and exits.
	Once bool
}

func (d *Daemon) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Daemon) sleep(ctx context.Context, t time.Time) error {
	if d.Sleep != nil {
		return d.Sleep(ctx, t)
	}
	wait := time.Until(t)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Run holds the home lock and serves schedules until ctx ends (SIGINT and
// SIGTERM arrive here through the process context): the in-flight scan is
// cancelled, its row is persisted as interrupted, the lock is released,
// and Run returns nil. A second daemon gets ErrLocked.
func (d *Daemon) Run(ctx context.Context) error {
	out := d.Out
	if out == nil {
		out = io.Discard
	}
	release, err := d.Lock.TryLock(filepath.Join(d.Home, LockFileName))
	if err != nil {
		return err
	}
	defer func() { _ = release() }()
	if d.Once {
		return d.serveDue(ctx, out)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := d.serveDue(ctx, out); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return nil
		}
		list, err := d.Store.ListSchedules(ctx)
		if err != nil {
			return err
		}
		now := d.now()
		wait := now.Add(PollInterval)
		for _, s := range list {
			if !s.Enabled {
				continue
			}
			if s.NextRun.Before(wait) {
				wait = s.NextRun
			}
		}
		_ = d.sleep(ctx, wait)
	}
}

// serveDue serves every due schedule once, earliest first. Schedules added
// or removed externally mid-pass are picked up by the re-list.
func (d *Daemon) serveDue(ctx context.Context, out io.Writer) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		list, err := d.Store.ListSchedules(ctx)
		if err != nil {
			return err
		}
		now := d.now()
		due := -1
		for i := range list {
			if !list[i].Enabled || list[i].NextRun.After(now) {
				continue
			}
			if due < 0 || list[i].NextRun.Before(list[due].NextRun) {
				due = i
			}
		}
		if due < 0 {
			return nil
		}
		if err := d.serveOne(ctx, out, list[due]); err != nil {
			return err
		}
	}
}

// serveOne runs a single due schedule and persists the outcome. Every path
// advances next_run — including refusals and skips — so a failing schedule
// can never hot-loop the daemon.
func (d *Daemon) serveOne(ctx context.Context, out io.Writer, s store.Schedule) error {
	started := d.now()
	sched, err := ParseCron(s.Cron)
	if err != nil {
		// Hand-edited cron the CLI would never have stored. Retry in an
		// hour rather than spinning or silently disabling the row.
		d.auditSkip(ctx, s.Name, "bad-cron", err.Error())
		d.line(out, started, s.Name, "skipped: bad cron", "")
		return d.Store.MarkScheduleRun(context.WithoutCancel(ctx), s.Name, started, "", "skipped: bad cron", started.Add(MinInterval))
	}
	req, err := d.Parse(s.Args)
	if err != nil {
		d.auditSkip(ctx, s.Name, "bad-args", err.Error())
		st := "skipped: bad args: " + firstLine(err.Error())
		d.line(out, started, s.Name, st, "")
		return d.Store.MarkScheduleRun(context.WithoutCancel(ctx), s.Name, started, "", st, advance(sched, s.NextRun, started))
	}
	req.Schedule = s.Name
	req.NonInteractive = true
	outcome, err := d.Scan(ctx, req)
	// Re-read the clock: the run took time, and the overlap check below
	// must compare against when it finished, not when it started.
	// Otherwise a run longer than its interval marks a next_run that is
	// already past, and the loop serves it again immediately.
	now := d.now()
	status := outcome.Status
	scanID := outcome.ScanID
	if err != nil {
		status = "failed: " + firstLine(err.Error())
		scanID = ""
	}
	if strings.HasPrefix(status, "skipped:") {
		// The run produced no scan for an operational reason (broken
		// scope file); audit it like every other skip.
		d.auditSkip(ctx, s.Name, "config", strings.TrimSpace(strings.TrimPrefix(status, "skipped:")))
	}
	status = truncate(status, maxStatusBytes)
	next := sched.Next(s.NextRun)
	if !next.After(now) {
		// A fire was missed while this run was in flight (or the row was
		// long-past-due at startup): collapse the backlog into one
		// audited skip and advance from now. Catch-up one, never N.
		d.auditSkip(ctx, s.Name, "overlap", "")
		next = sched.Next(now)
	}
	// Persist even when shutting down: SIGINT/SIGTERM must leave every
	// row advanced (spec: persist next_run, release lock, exit 0).
	if err := d.Store.MarkScheduleRun(context.WithoutCancel(ctx), s.Name, started, scanID, status, next); err != nil {
		return err
	}
	d.line(out, started, s.Name, status, scanID)
	if scanID != "" && d.Notify != nil && ctx.Err() == nil {
		if err := d.Notify.Send(ctx, outcome.Summary); err != nil && d.Audit != nil {
			_ = d.Audit.Log(context.WithoutCancel(ctx), audit.ActionSchedule, "", map[string]any{
				"op": "notify-failed", "schedule": s.Name, "scan_id": scanID, "error": firstLine(err.Error()),
			})
		}
	}
	return nil
}

// advance computes the fire after the one just served; when that is still
// past (backlog), it advances from now instead.
func advance(sched cron.Schedule, served, now time.Time) time.Time {
	if next := sched.Next(served); next.After(now) {
		return next
	}
	return sched.Next(now)
}

func (d *Daemon) auditSkip(ctx context.Context, name, reason, errText string) {
	if d.Audit == nil {
		return
	}
	detail := map[string]any{"schedule": name, "reason": reason}
	if errText != "" {
		detail["error"] = firstLine(errText)
	}
	_ = d.Audit.Log(context.WithoutCancel(ctx), audit.ActionScheduleSkipped, "", detail)
}

func (d *Daemon) line(out io.Writer, now time.Time, name, status, scanID string) {
	if scanID != "" {
		fmt.Fprintf(out, "%s %s: %s scan=%s\n", now.Format(time.RFC3339), name, status, scanID)
		return
	}
	fmt.Fprintf(out, "%s %s: %s\n", now.Format(time.RFC3339), name, status)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// LockState probes the home lock for doctor: whether a daemon holds it,
// and the recorded pid when it does.
func LockState(home string) (running bool, pid int) {
	path := filepath.Join(home, LockFileName)
	if _, err := os.Stat(path); err != nil {
		return false, 0
	}
	release, err := SystemLocker.TryLock(path)
	if err == nil {
		_ = release()
		return false, 0
	}
	var locked *LockedError
	if errors.As(err, &locked) {
		return true, locked.PID
	}
	return false, 0
}
