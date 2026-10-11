package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func sampleSchedule() Schedule {
	return Schedule{
		Name: "weekly", Cron: "@weekly", Args: []string{"scan", ".", "--profile", "standard"},
		Enabled: true, CreatedBy: "tester", CreatedAt: time.Now().Truncate(time.Second),
		NextRun: time.Now().Add(time.Hour).Truncate(time.Second),
	}
}

func TestScheduleCRUD(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	want := sampleSchedule()
	if err := s.CreateSchedule(ctx, want); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSchedule(ctx, want); err != ErrScheduleExists && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("dup: %v", err)
	}
	got, err := s.GetSchedule(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != want.Name || got.Cron != want.Cron || !got.Enabled || got.CreatedBy != "tester" ||
		len(got.Args) != 4 || got.Args[0] != "scan" || got.LastRun != nil || got.LastStatus != "" {
		t.Fatalf("got %+v", got)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.NextRun.Equal(want.NextRun) {
		t.Fatalf("times %+v", got)
	}
	if _, err := s.GetSchedule(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
	rows, err := s.ListSchedules(ctx)
	if err != nil || len(rows) != 1 || rows[0].Name != "weekly" {
		t.Fatalf("list: %v %v", rows, err)
	}
	next := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	at := time.Now().Truncate(time.Second)
	if err := s.MarkScheduleRun(ctx, "weekly", at, "scan1", "ok", next); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSchedule(ctx, "weekly")
	if got.LastScanID != "scan1" || got.LastStatus != "ok" || got.LastRun == nil || !got.LastRun.Equal(at) || !got.NextRun.Equal(next) {
		t.Fatalf("marked: %+v", got)
	}
	if err := s.SetScheduleEnabled(ctx, "weekly", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSchedule(ctx, "weekly"); got.Enabled {
		t.Fatal("still enabled")
	}
	later := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	if err := s.SetScheduleEnabled(ctx, "weekly", true, later); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSchedule(ctx, "weekly"); !got.Enabled || !got.NextRun.Equal(later) {
		t.Fatalf("enabled: %+v", got)
	}
	if err := s.DeleteSchedule(ctx, "weekly"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSchedule(ctx, "weekly"); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	if err := s.DeleteSchedule(ctx, "weekly"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

// Oversized args_json is refused at decode so a hand-edited row cannot
// OOM the daemon's list loop.
func TestScheduleArgsCap(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	sc := sampleSchedule()
	sc.Args = []string{"scan", strings.Repeat("x", maxScheduleArgsBytes)}
	if err := s.CreateSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSchedule(ctx, sc.Name); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("cap: %v", err)
	}
	if _, err := s.ListSchedules(ctx); err == nil {
		t.Fatal("list accepted the oversized row")
	}
}

// Rolling back 0004 drops the schedules table; migrating back up restores
// it empty. Guards the down path of the newest migration.
func TestScheduleRollback(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateSchedule(ctx, sampleSchedule()); err != nil {
		t.Fatal(err)
	}
	if err := s.MigrateDown(ctx, 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListSchedules(ctx); err == nil {
		t.Fatal("schedules table survived rollback")
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListSchedules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected empty table after up, got %d rows", len(rows))
	}
}
