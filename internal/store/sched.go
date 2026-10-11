package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Schedule is one stored row: the cron expression, the `scan ...` argv,
// and the state of the most recent run.
type Schedule struct {
	Name, Cron string
	Args       []string
	Enabled    bool
	CreatedBy  string
	CreatedAt  time.Time
	NextRun    time.Time
	LastRun    *time.Time
	LastScanID string
	LastStatus string
}

// ErrScheduleExists is returned when a schedule is created twice; `add`
// must fail rather than silently clobber the stored argv.
var ErrScheduleExists = errors.New("schedule already exists")

// maxScheduleArgsBytes caps args_json before decode. The daemon re-validates
// the decoded argv on every run (C3), so a hand-edited row can only refuse,
// never smuggle flags past validation — but a huge TEXT must not OOM decode.
const maxScheduleArgsBytes = 64 << 10

func scheduleArgs(raw string) ([]string, error) {
	if len(raw) > maxScheduleArgsBytes {
		return nil, fmt.Errorf("args_json exceeds %d bytes", maxScheduleArgsBytes)
	}
	var args []string
	dec := json.NewDecoder(strings.NewReader(raw))
	if err := dec.Decode(&args); err != nil {
		return nil, fmt.Errorf("args_json: %w", err)
	}
	return args, nil
}

func scanSchedule(row *sql.Row) (Schedule, error) {
	return scanScheduleRow(row)
}

func scanScheduleRow(r interface {
	Scan(dest ...any) error
}) (Schedule, error) {
	var s Schedule
	var enabled int
	var createdAt, nextRun string
	var lastRun, lastScanID, lastStatus sql.NullString
	var argsRaw string
	if err := r.Scan(&s.Name, &s.Cron, &argsRaw, &enabled, &s.CreatedBy, &createdAt, &lastRun, &lastScanID, &lastStatus, &nextRun); err != nil {
		return Schedule{}, err
	}
	args, err := scheduleArgs(argsRaw)
	if err != nil {
		return Schedule{}, fmt.Errorf("schedule %q: %w", s.Name, err)
	}
	s.Args = args
	s.Enabled = enabled != 0
	s.CreatedAt = parseTime(createdAt)
	s.NextRun = parseTime(nextRun)
	if lastRun.Valid {
		t := parseTime(lastRun.String)
		s.LastRun = &t
	}
	s.LastScanID = lastScanID.String
	s.LastStatus = lastStatus.String
	return s, nil
}

// CreateSchedule inserts a schedule; an existing name fails instead of
// overwriting (see ErrScheduleExists).
func (s *Store) CreateSchedule(ctx context.Context, sc Schedule) error {
	args := marshalJSON(sc.Args)
	_, err := s.db.ExecContext(ctx, `INSERT INTO schedules(name, cron, args_json, enabled, created_by, created_at, next_run)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sc.Name, sc.Cron, args, boolInt(sc.Enabled), sc.CreatedBy, fmtTime(sc.CreatedAt), fmtTime(sc.NextRun))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("schedule %q: %w", sc.Name, ErrScheduleExists)
		}
		return fmt.Errorf("create schedule: %w", err)
	}
	return nil
}

// GetSchedule loads one schedule by name.
func (s *Store) GetSchedule(ctx context.Context, name string) (Schedule, error) {
	sc, err := scanSchedule(s.db.QueryRowContext(ctx, `SELECT name, cron, args_json, enabled, created_by, created_at, last_run, last_scan_id, last_status, next_run FROM schedules WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	return sc, err
}

// ListSchedules loads all schedules ordered by name.
func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, cron, args_json, enabled, created_by, created_at, last_run, last_scan_id, last_status, next_run FROM schedules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only iteration; Close error unactionable
	var out []Schedule
	for rows.Next() {
		sc, err := scanScheduleRow(rows)
		if err != nil {
			rows.Close() //nolint:errcheck // returning the scan error already
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// DeleteSchedule removes a schedule; deleting a missing name is not an error.
func (s *Store) DeleteSchedule(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM schedules WHERE name = ?`, name)
	return err
}

// MarkScheduleRun records a completed (or refused/failed/timed-out) run and
// advances next_run. Every serve advances, even refusals, so a failing
// schedule can never hot-loop the daemon. at is the run time (the daemon's
// clock, fake in tests).
func (s *Store) MarkScheduleRun(ctx context.Context, name string, at time.Time, scanID, status string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schedules SET last_run = ?, last_scan_id = ?, last_status = ?, next_run = ? WHERE name = ?`,
		fmtTime(at), scanID, status, fmtTime(next), name)
	return err
}

// SetScheduleEnabled flips a schedule on or off. Enabling recomputes
// next_run from now (the caller passes it); disabling keeps the row.
func (s *Store) SetScheduleEnabled(ctx context.Context, name string, enabled bool, next time.Time) error {
	var err error
	if enabled {
		_, err = s.db.ExecContext(ctx, `UPDATE schedules SET enabled = 1, next_run = ? WHERE name = ?`, fmtTime(next), name)
	} else {
		_, err = s.db.ExecContext(ctx, `UPDATE schedules SET enabled = 0 WHERE name = ?`, name)
	}
	return err
}
