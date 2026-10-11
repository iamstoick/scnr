-- Scheduled scans (Phase 4c). args_json is the stored `scan ...` argv as a
-- JSON array; next_run is RFC3339. last_* describe the most recent run.
CREATE TABLE schedules (name TEXT PRIMARY KEY, cron TEXT NOT NULL, args_json TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, last_run TEXT, last_scan_id TEXT, last_status TEXT, next_run TEXT NOT NULL);
