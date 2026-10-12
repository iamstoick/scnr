// Package store owns the SQLite database. Every query uses `?` placeholders
// via database/sql; nothing outside this package touches *sql.DB.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver

	"github.com/iamstoick/scnr/internal/domain"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store wraps the database handle.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the database at path and applies pending
// migrations. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(ON)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// One connection: SQLite has a single writer and the in-memory DSN is
	// per-connection. The Writer goroutine serialises writes anyway.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.Migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close the database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the DB file path.
func (s *Store) Path() string { return s.path }

// Ping checks the connection.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

type migration struct {
	version int
	name    string
	up      string
	down    string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	byVersion := map[int]*migration{}
	for _, e := range entries {
		name := e.Name()
		parts := strings.SplitN(name, "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad migration filename %q", name)
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("bad migration version in %q", name)
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		m := byVersion[v]
		if m == nil {
			m = &migration{version: v}
			byVersion[v] = m
		}
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			m.up = string(body)
			m.name = strings.TrimSuffix(parts[1], ".up.sql")
		case strings.HasSuffix(name, ".down.sql"):
			m.down = string(body)
		default:
			return nil, fmt.Errorf("unexpected migration file %q", name)
		}
	}
	out := make([]migration, 0, len(byVersion))
	for _, m := range byVersion {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate applies all pending up migrations, each in its own transaction.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range ms {
		if m.version <= current {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.up); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d %s: %w", m.version, m.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, m.version, now()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ErrAuditLoss is returned by MigrateDown when audit_log holds rows and the
// caller has not explicitly accepted losing them.
var ErrAuditLoss = errors.New("rolling back would destroy audit_log rows")

// MigrateDown rolls back the latest n migrations. The audit log is
// append-only, so when it has rows the rollback is refused unless
// allowAuditLoss is set (the CLI writes an audit row first).
func (s *Store) MigrateDown(ctx context.Context, n int, allowAuditLoss bool) error {
	if !allowAuditLoss {
		rows, err := s.AuditRowCount(ctx)
		if err != nil {
			return err
		}
		if rows > 0 {
			return fmt.Errorf("%w (%d rows)", ErrAuditLoss, rows)
		}
	}
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	for i := len(ms) - 1; i >= 0 && n > 0; i-- {
		m := ms[i]
		if m.version > current {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.down); err != nil {
			tx.Rollback()
			return fmt.Errorf("rollback %d %s: %w", m.version, m.name, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = ?`, m.version); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		n--
	}
	return nil
}

// SchemaVersion returns the highest applied migration version (0 if none).
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// LatestMigrationVersion is the newest embedded migration.
func LatestMigrationVersion() (int, error) {
	ms, err := loadMigrations()
	if err != nil || len(ms) == 0 {
		return 0, err
	}
	return ms[len(ms)-1].version, nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func marshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

// ErrNotFound is returned by Get* methods.
var ErrNotFound = errors.New("not found")

// withTx runs fn inside a transaction, committing on nil and rolling back
// on error.
func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- scans ----

// InsertScan records a scan start, its targets, and nothing else yet.
func (s *Store) InsertScan(ctx context.Context, sc *domain.Scan) error {
	return s.withTx(ctx, func(tx *sql.Tx) error { return s.insertScan(ctx, tx, sc) })
}

func (s *Store) insertScan(ctx context.Context, tx *sql.Tx, sc *domain.Scan) error {
	meta := map[string]any{"consent_at": sc.Consent.At}
	if sc.Schedule != "" {
		meta["schedule"] = sc.Schedule
	}
	if sc.Intrusive.Ran {
		targets := sc.Intrusive.Targets
		if targets == nil {
			targets = []string{}
		}
		meta["intrusive"] = map[string]any{"targets": targets, "probes": sc.Intrusive.Probes}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO scans(id, started_at, profile, target_set_hash, scope_hash, consent_method, consent_by, partial, meta)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		sc.ID, fmtTime(sc.StartedAt), sc.Profile, sc.TargetSetHash, sc.ScopeHash, sc.Consent.Method, sc.Consent.By,
		marshalJSON(meta))
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}
	for _, t := range sc.Targets {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_targets(scan_id, raw, type, value, public) VALUES (?, ?, ?, ?, ?)`,
			sc.ID, t.Raw, string(t.Type), t.Value, boolInt(t.Public)); err != nil {
			return err
		}
	}
	return nil
}

// FinishScan writes the final state: engines, posture, partial flag, exit code.
func (s *Store) FinishScan(ctx context.Context, sc *domain.Scan) error {
	return s.withTx(ctx, func(tx *sql.Tx) error { return s.finishScan(ctx, tx, sc) })
}

func (s *Store) finishScan(ctx context.Context, tx *sql.Tx, sc *domain.Scan) error {
	_, err := tx.ExecContext(ctx, `UPDATE scans SET finished_at = ?, partial = ?, score = ?, grade = ?, exit_code = ? WHERE id = ?`,
		fmtTime(sc.FinishedAt), boolInt(sc.Partial), sc.Posture.Score, sc.Posture.Grade, sc.ExitCode, sc.ID)
	if err != nil {
		return err
	}
	for _, e := range sc.Engines {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_engines(scan_id, name, version, status, duration_ms, error) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(scan_id, name) DO UPDATE SET version=excluded.version, status=excluded.status, duration_ms=excluded.duration_ms, error=excluded.error`,
			sc.ID, e.Name, e.Version, e.Status, e.Duration.Milliseconds(), e.Error); err != nil {
			return err
		}
	}
	return nil
}

// SetScanMetaValue merges one key into scans.meta, preserving the rest.
// RunScan uses it to record the final intrusive probe count after the
// engines complete.
func (s *Store) SetScanMetaValue(ctx context.Context, id, key string, value any) error {
	var cur sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT meta FROM scans WHERE id = ?`, id).Scan(&cur); err != nil {
		return fmt.Errorf("read scan meta: %w", err)
	}
	m := map[string]any{}
	if cur.Valid && cur.String != "" {
		if err := json.Unmarshal([]byte(cur.String), &m); err != nil {
			return fmt.Errorf("parse scan meta: %w", err)
		}
	}
	m[key] = value
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode scan meta: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE scans SET meta = ? WHERE id = ?`, string(b), id); err != nil {
		return fmt.Errorf("write scan meta: %w", err)
	}
	return nil
}

// GetScan loads a scan with targets and engines. id may be "latest".
func (s *Store) GetScan(ctx context.Context, id string) (*domain.Scan, error) {
	if id == "latest" {
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM scans ORDER BY started_at DESC LIMIT 1`).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	}
	sc := &domain.Scan{ID: id}
	var started, finished, grade sql.NullString
	var partial int
	var score, exit sql.NullInt64
	var meta sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT started_at, finished_at, profile, target_set_hash, scope_hash, consent_method, consent_by, partial, score, grade, exit_code, meta FROM scans WHERE id = ?`, id).
		Scan(&started, &finished, &sc.Profile, &sc.TargetSetHash, &sc.ScopeHash, &sc.Consent.Method, &sc.Consent.By, &partial, &score, &grade, &exit, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if meta.Valid {
		var m map[string]any
		if err := json.Unmarshal([]byte(meta.String), &m); err == nil {
			sc.Schedule, _ = m["schedule"].(string)
			if im, ok := m["intrusive"].(map[string]any); ok {
				sc.Intrusive.Ran = true
				if ts, ok := im["targets"].([]any); ok {
					for _, v := range ts {
						if s, ok := v.(string); ok {
							sc.Intrusive.Targets = append(sc.Intrusive.Targets, s)
						}
					}
				}
				if p, ok := im["probes"].(float64); ok {
					sc.Intrusive.Probes = int(p)
				}
			}
		}
	}
	sc.StartedAt = parseTime(started.String)
	sc.FinishedAt = parseTime(finished.String)
	sc.Partial = partial == 1
	sc.Posture.Score = int(score.Int64)
	sc.Posture.Grade = grade.String
	sc.Posture.Partial = sc.Partial
	sc.ExitCode = int(exit.Int64)

	rows, err := s.db.QueryContext(ctx, `SELECT raw, type, value, public FROM scan_targets WHERE scan_id = ?`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t domain.Target
		var pub int
		var typ string
		if err := rows.Scan(&t.Raw, &typ, &t.Value, &pub); err != nil {
			rows.Close()
			return nil, err
		}
		t.Type = domain.TargetType(typ)
		t.Public = pub == 1
		sc.Targets = append(sc.Targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.db.QueryContext(ctx, `SELECT name, version, status, duration_ms, error FROM scan_engines WHERE scan_id = ? ORDER BY name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e domain.EngineRun
		var ver, errs sql.NullString
		var ms sql.NullInt64
		if err := rows.Scan(&e.Name, &ver, &e.Status, &ms, &errs); err != nil {
			return nil, err
		}
		e.Version, e.Error = ver.String, errs.String
		e.Duration = time.Duration(ms.Int64) * time.Millisecond
		sc.Engines = append(sc.Engines, e)
	}
	return sc, rows.Err()
}

// ScanSummary is one row of `scan list`.
type ScanSummary struct {
	ID        string
	StartedAt time.Time
	Profile   string
	Targets   int
	Findings  int
	Score     int
	Grade     string
	Partial   bool
}

// ListScans returns the most recent scans, paged.
func (s *Store) ListScans(ctx context.Context, limit, offset int) ([]ScanSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.started_at, s.profile, s.partial, COALESCE(s.score, 0), COALESCE(s.grade, ''),
		(SELECT COUNT(*) FROM scan_targets t WHERE t.scan_id = s.id),
		(SELECT COUNT(*) FROM finding_occurrences o WHERE o.scan_id = s.id)
		FROM scans s ORDER BY s.started_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanSummary
	for rows.Next() {
		var r ScanSummary
		var started string
		var partial int
		if err := rows.Scan(&r.ID, &started, &r.Profile, &partial, &r.Score, &r.Grade, &r.Targets, &r.Findings); err != nil {
			return nil, err
		}
		r.StartedAt = parseTime(started)
		r.Partial = partial == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// PreviousScanScore returns the score of the most recent finished scan with
// the same target set before `before`. ok=false when none exists.
func (s *Store) PreviousScanScore(ctx context.Context, targetSetHash, excludeID string) (int, bool, error) {
	var score sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT score FROM scans WHERE target_set_hash = ? AND id != ? AND finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 1`, targetSetHash, excludeID).Scan(&score)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return int(score.Int64), score.Valid, nil
}

// ---- assets ----

// UpsertAsset inserts or refreshes an asset by key and returns its ID.
func (s *Store) UpsertAsset(ctx context.Context, a domain.Asset) (string, error) {
	return upsertAsset(ctx, s.db, a)
}

type execQuerier interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

func upsertAsset(ctx context.Context, q execQuerier, a domain.Asset) (string, error) {
	if a.ID == "" {
		a.ID = domain.NewID()
	}
	if a.Labels == nil {
		a.Labels = map[string]string{}
	}
	ts := now()
	if !a.LastSeen.IsZero() {
		ts = fmtTime(a.LastSeen)
	}
	_, err := q.ExecContext(ctx, `INSERT INTO assets(id, key, type, name, labels, public, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET last_seen = excluded.last_seen, public = excluded.public, name = excluded.name`,
		a.ID, a.Key, string(a.Type), a.Name, marshalJSON(a.Labels), boolInt(a.Public), ts, ts)
	if err != nil {
		return "", fmt.Errorf("upsert asset %s: %w", a.Key, err)
	}
	var id string
	if err := q.QueryRowContext(ctx, `SELECT id FROM assets WHERE key = ?`, a.Key).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

// ListAssets pages assets.
func (s *Store) ListAssets(ctx context.Context, limit, offset int) ([]domain.Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, key, type, COALESCE(name, ''), labels, public, first_seen, last_seen FROM assets ORDER BY last_seen DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Asset
	for rows.Next() {
		var a domain.Asset
		var typ, labels, first, last string
		var pub int
		if err := rows.Scan(&a.ID, &a.Key, &typ, &a.Name, &labels, &pub, &first, &last); err != nil {
			return nil, err
		}
		a.Type = domain.TargetType(typ)
		a.Public = pub == 1
		a.FirstSeen, a.LastSeen = parseTime(first), parseTime(last)
		_ = json.Unmarshal([]byte(labels), &a.Labels)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- findings ----

// FindingFilter narrows list queries. Zero values mean "any".
type FindingFilter struct {
	ScanID      string
	AssetKey    string
	MinSeverity *domain.Severity
	Status      domain.Status
	Limit       int
	Offset      int
}

const findingColumns = `f.fingerprint, a.key, f.rule_id, f.engine, f.title, f.severity, f.confidence,
	COALESCE(f.what,''), COALESCE(f.why,''), COALESCE(f.fix,''), COALESCE(f.location,''), f.cves, COALESCE(f.cwe,''),
	f.cvss_vector, f.cvss_score, f.epss, f.kev, f.risk, f.refs, f.status, f.first_seen, f.last_seen`

func scanFinding(rows interface{ Scan(...any) error }) (domain.Finding, error) {
	var f domain.Finding
	var sev, conf, kev int
	var cves, refs, first, last, status string
	var vec sql.NullString
	var cvss, epss sql.NullFloat64
	if err := rows.Scan(&f.Fingerprint, &f.AssetKey, &f.RuleID, &f.Engine, &f.Title, &sev, &conf,
		&f.WhatItIs, &f.WhyItMatters, &f.HowToFix, &f.Location, &cves, &f.CWE,
		&vec, &cvss, &epss, &kev, &f.Risk, &refs, &status, &first, &last); err != nil {
		return f, err
	}
	f.ID = f.Fingerprint
	f.Severity, f.Confidence = domain.Severity(sev), domain.Confidence(conf)
	f.KEV = kev == 1
	f.Status = domain.Status(status)
	f.FirstSeen, f.LastSeen = parseTime(first), parseTime(last)
	_ = json.Unmarshal([]byte(cves), &f.CVEs)
	_ = json.Unmarshal([]byte(refs), &f.References)
	if f.CVEs == nil {
		f.CVEs = []string{}
	}
	if f.References == nil {
		f.References = []string{}
	}
	if vec.Valid || cvss.Valid {
		f.CVSS = &domain.CVSS{Vector: vec.String, Score: cvss.Float64}
	}
	if epss.Valid {
		v := epss.Float64
		f.EPSS = &v
	}
	f.Evidence = []domain.Evidence{}
	return f, nil
}

// ListFindings returns findings matching the filter, ordered by risk desc.
func (s *Store) ListFindings(ctx context.Context, fl FindingFilter) ([]domain.Finding, error) {
	if fl.Limit <= 0 {
		fl.Limit = 50
	}
	// Build the WHERE clause from a fixed set of fragments; values are
	// always bound as parameters.
	var where []string
	var args []any
	if fl.ScanID != "" {
		where = append(where, `f.fingerprint IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?)`)
		args = append(args, fl.ScanID)
	}
	if fl.AssetKey != "" {
		where = append(where, `a.key = ?`)
		args = append(args, fl.AssetKey)
	}
	if fl.MinSeverity != nil {
		where = append(where, `f.severity >= ?`)
		args = append(args, int(*fl.MinSeverity))
	}
	if fl.Status != "" {
		where = append(where, `f.status = ?`)
		args = append(args, string(fl.Status))
	}
	q := `SELECT ` + findingColumns + ` FROM findings f JOIN assets a ON a.id = f.asset_id`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY f.risk DESC, f.fingerprint LIMIT ? OFFSET ?`
	args = append(args, fl.Limit, fl.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		if fl.ScanID != "" {
			f.ScanID = fl.ScanID
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetFinding loads one finding with its evidence (latest scan's rows).
func (s *Store) GetFinding(ctx context.Context, fingerprint string) (*domain.Finding, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.fingerprint = ?`, fingerprint)
	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ev, err := s.evidenceFor(ctx, fingerprint, "")
	if err != nil {
		return nil, err
	}
	f.Evidence = ev
	return &f, nil
}

func (s *Store) evidenceFor(ctx context.Context, fingerprint, scanID string) ([]domain.Evidence, error) {
	var rows *sql.Rows
	var err error
	if scanID == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT kind, COALESCE(location,''), redacted, hash FROM evidence WHERE fingerprint = ? AND scan_id = (SELECT scan_id FROM evidence WHERE fingerprint = ? ORDER BY id DESC LIMIT 1) ORDER BY id LIMIT ?`, fingerprint, fingerprint, domain.MaxEvidencePerFinding)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT kind, COALESCE(location,''), redacted, hash FROM evidence WHERE fingerprint = ? AND scan_id = ? ORDER BY id LIMIT ?`, fingerprint, scanID, domain.MaxEvidencePerFinding)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Evidence{}
	for rows.Next() {
		var e domain.Evidence
		if err := rows.Scan(&e.Kind, &e.Location, &e.Redacted, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountFindings returns the number of findings seen in a scan.
func (s *Store) CountFindings(ctx context.Context, scanID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?`, scanID).Scan(&n)
	return n, err
}

// FindingIterator pages findings for one scan, 500 at a time, so reporters
// never hold a whole scan in memory.
type FindingIterator struct {
	s      *Store
	scanID string
	offset int
	buf    []domain.Finding
	err    error
	done   bool
}

// PageSize for reporters (Section 8).
const PageSize = 500

// Iterate returns an iterator over a scan's findings ordered by risk desc.
func (s *Store) Iterate(scanID string) *FindingIterator {
	return &FindingIterator{s: s, scanID: scanID}
}

// Next returns the next finding (with evidence) or false when exhausted.
func (it *FindingIterator) Next(ctx context.Context) (domain.Finding, bool) {
	if len(it.buf) == 0 && !it.done {
		page, err := it.s.ListFindings(ctx, FindingFilter{ScanID: it.scanID, Limit: PageSize, Offset: it.offset})
		if err != nil {
			it.err = err
			it.done = true
			return domain.Finding{}, false
		}
		it.offset += len(page)
		if len(page) < PageSize {
			it.done = true
		}
		it.buf = page
	}
	if len(it.buf) == 0 {
		return domain.Finding{}, false
	}
	f := it.buf[0]
	it.buf = it.buf[1:]
	ev, err := it.s.evidenceFor(ctx, f.Fingerprint, it.scanID)
	if err != nil {
		it.err = err
		it.done = true
		return domain.Finding{}, false
	}
	f.Evidence = ev
	return f, true
}

// Err reports any iteration error.
func (it *FindingIterator) Err() error { return it.err }

// ---- verifications ----

// Verification is a stored ownership proof.
type Verification struct {
	Host       string
	Method     string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

// PutVerification upserts a verification row.
func (s *Store) PutVerification(ctx context.Context, v Verification) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO verifications(host, method, verified_at, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET method = excluded.method, verified_at = excluded.verified_at, expires_at = excluded.expires_at`,
		strings.ToLower(v.Host), v.Method, fmtTime(v.VerifiedAt), fmtTime(v.ExpiresAt))
	return err
}

// GetVerification returns the row for host or ErrNotFound.
func (s *Store) GetVerification(ctx context.Context, host string) (*Verification, error) {
	var v Verification
	var at, exp string
	err := s.db.QueryRowContext(ctx, `SELECT host, method, verified_at, expires_at FROM verifications WHERE host = ?`, strings.ToLower(host)).Scan(&v.Host, &v.Method, &at, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.VerifiedAt, v.ExpiresAt = parseTime(at), parseTime(exp)
	return &v, nil
}

// ---- audit (append-only: this file contains no UPDATE/DELETE for audit_log) ----

// AuditEntry is one audit row.
type AuditEntry struct {
	ID     int64
	TS     time.Time
	Actor  string
	Action string
	ScanID string
	Detail json.RawMessage
}

// AppendAudit inserts an audit row.
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) (int64, error) {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if len(e.Detail) == 0 {
		e.Detail = json.RawMessage("{}")
	}
	var scanID any
	if e.ScanID != "" {
		scanID = e.ScanID
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit_log(ts, actor, action, scan_id, detail) VALUES (?, ?, ?, ?, ?)`,
		fmtTime(e.TS), e.Actor, e.Action, scanID, string(e.Detail))
	if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	return res.LastInsertId()
}

// AuditRowCount returns the number of audit rows (0 when the table is absent).
func (s *Store) AuditRowCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return 0, nil
	}
	return n, err
}

// ListAudit returns audit rows, newest first; scanID filters when non-empty.
func (s *Store) ListAudit(ctx context.Context, scanID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if scanID != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT id, ts, actor, action, COALESCE(scan_id,''), detail FROM audit_log WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, ts, actor, action, COALESCE(scan_id,''), detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts, detail string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.ScanID, &detail); err != nil {
			return nil, err
		}
		e.TS = parseTime(ts)
		e.Detail = json.RawMessage(detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- vulndb ----

// KEVEntry is one CISA KEV row.
type KEVEntry struct {
	CVE     string
	Added   string
	Due     string
	Product string
}

// EPSSEntry is one EPSS row.
type EPSSEntry struct {
	CVE        string
	Score      float64
	Percentile float64
}

// ReplaceKEV replaces the kev table atomically.
func (s *Store) ReplaceKEV(ctx context.Context, entries []KEVEntry, version string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error { return replaceKEV(ctx, tx, entries, version) })
}

func replaceKEV(ctx context.Context, tx *sql.Tx, entries []KEVEntry, version string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx, `INSERT INTO kev(cve, added, due, product) VALUES (?, ?, ?, ?) ON CONFLICT(cve) DO NOTHING`, e.CVE, e.Added, e.Due, e.Product); err != nil {
			return err
		}
	}
	return setMeta(ctx, tx, "kev", version)
}

// ReplaceEPSS replaces the epss table atomically.
func (s *Store) ReplaceEPSS(ctx context.Context, entries []EPSSEntry, version string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error { return replaceEPSS(ctx, tx, entries, version) })
}

func replaceEPSS(ctx context.Context, tx *sql.Tx, entries []EPSSEntry, version string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM epss`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO epss(cve, score, percentile) VALUES (?, ?, ?) ON CONFLICT(cve) DO UPDATE SET score = excluded.score, percentile = excluded.percentile`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.CVE, e.Score, e.Percentile); err != nil {
			return err
		}
	}
	return setMeta(ctx, tx, "epss", version)
}

func setMeta(ctx context.Context, q execQuerier, source, version string) error {
	_, err := q.ExecContext(ctx, `INSERT INTO vulndb_meta(source, updated_at, version) VALUES (?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET updated_at = excluded.updated_at, version = excluded.version`, source, now(), version)
	return err
}

// VulnDBMeta describes one vulndb source.
type VulnDBMeta struct {
	Source    string
	UpdatedAt time.Time
	Version   string
	Rows      int
}

// vulnDBTables maps each vulndb_meta source to its row table. Table names
// come from this fixed list, never from input.
var vulnDBTables = []struct{ source, table string }{{"kev", "kev"}, {"epss", "epss"}, {SourceOSVOffline, "osv_affected"}}

// VulnDBStatus returns metadata for kev, epss and osv-offline (absent
// sources have zero UpdatedAt).
func (s *Store) VulnDBStatus(ctx context.Context) ([]VulnDBMeta, error) {
	out := make([]VulnDBMeta, len(vulnDBTables))
	for i, t := range vulnDBTables {
		out[i].Source = t.source
		var at string
		var ver sql.NullString
		err := s.db.QueryRowContext(ctx, `SELECT updated_at, version FROM vulndb_meta WHERE source = ?`, t.source).Scan(&at, &ver)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err == nil {
			out[i].UpdatedAt = parseTime(at)
			out[i].Version = ver.String
		}
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+t.table).Scan(&out[i].Rows); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// LookupKEV reports whether cve is in the KEV catalogue.
func (s *Store) LookupKEV(ctx context.Context, cve string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kev WHERE cve = ?`, strings.ToUpper(cve)).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// LookupEPSS returns the EPSS score for cve; ok=false if unknown.
func (s *Store) LookupEPSS(ctx context.Context, cve string) (float64, bool, error) {
	var score float64
	err := s.db.QueryRowContext(ctx, `SELECT score FROM epss WHERE cve = ?`, strings.ToUpper(cve)).Scan(&score)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return score, true, nil
}

// VulnCacheGet returns a cached OSV body if fresher than maxAge.
func (s *Store) VulnCacheGet(ctx context.Context, id string, maxAge time.Duration) ([]byte, bool, error) {
	var body, fetched string
	err := s.db.QueryRowContext(ctx, `SELECT body, fetched_at FROM vuln_cache WHERE id = ?`, id).Scan(&body, &fetched)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if time.Since(parseTime(fetched)) > maxAge {
		return nil, false, nil
	}
	return []byte(body), true, nil
}

// VulnCachePut stores an OSV body.
func (s *Store) VulnCachePut(ctx context.Context, id string, body []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vuln_cache(id, body, fetched_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET body = excluded.body, fetched_at = excluded.fetched_at`, id, string(body), now())
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
