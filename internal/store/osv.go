package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// SourceOSVOffline is the vulndb_meta source for bundle-loaded OSV data.
const SourceOSVOffline = "osv-offline"

// AffectedRecord is one osv_affected row: a vulnerability's entry for one
// package. Body is the normalised bundle record (sca.Record JSON).
type AffectedRecord struct {
	ID           string
	Ecosystem    string
	Name         string
	VersionsJSON string
	RangesJSON   string
	Body         []byte
}

// AffectedFor returns every record for a package (exact ecosystem and name).
func (s *Store) AffectedFor(ctx context.Context, ecosystem, name string) ([]AffectedRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ecosystem, name, versions_json, ranges_json, body FROM osv_affected WHERE ecosystem = ? AND name = ? ORDER BY id`, ecosystem, name)
	if err != nil {
		return nil, err
	}
	return scanAffected(rows)
}

// AffectedByIDs returns every record for the given vulnerability IDs
// (chunked IN queries).
func (s *Store) AffectedByIDs(ctx context.Context, ids []string) ([]AffectedRecord, error) {
	var out []AffectedRecord
	for _, chunk := range chunks(ids, inChunk) {
		ph := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for i, id := range chunk {
			ph[i], args[i] = "?", id
		}
		rows, err := s.db.QueryContext(ctx, `SELECT id, ecosystem, name, versions_json, ranges_json, body FROM osv_affected WHERE id IN (`+strings.Join(ph, ",")+`) ORDER BY id, ecosystem, name`, args...)
		if err != nil {
			return nil, err
		}
		got, err := scanAffected(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

func scanAffected(rows *sql.Rows) ([]AffectedRecord, error) {
	defer rows.Close()
	var out []AffectedRecord
	for rows.Next() {
		var r AffectedRecord
		var body string
		if err := rows.Scan(&r.ID, &r.Ecosystem, &r.Name, &r.VersionsJSON, &r.RangesJSON, &body); err != nil {
			return nil, err
		}
		r.Body = []byte(body)
		out = append(out, r)
	}
	return out, rows.Err()
}

// OSVAffectedCount returns the number of offline OSV rows.
func (s *Store) OSVAffectedCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM osv_affected`).Scan(&n)
	return n, err
}

// OfflineLoad stages a bundle's rows in one transaction and swaps them in
// at Commit; any error before that, or Rollback, leaves osv_affected, kev,
// epss and vulndb_meta exactly as they were (a half-loaded bundle never
// exists). The staging table lives inside the transaction, so a crash
// mid-load is undone by SQLite's journal.
type OfflineLoad struct {
	tx    *sql.Tx
	stmt  *sql.Stmt
	rows  int64
	done  bool
	store *Store
}

// ErrLoadFinished is returned when an OfflineLoad is used after Commit or Rollback.
var ErrLoadFinished = errors.New("offline load already finished")

// BeginOfflineLoad opens the load transaction and creates the staging table.
func (s *Store) BeginOfflineLoad(ctx context.Context) (*OfflineLoad, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	l := &OfflineLoad{tx: tx, store: s}
	for _, q := range []string{
		`DROP TABLE IF EXISTS osv_affected_staging`,
		`CREATE TABLE osv_affected_staging (id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
			versions_json TEXT NOT NULL DEFAULT '[]', ranges_json TEXT NOT NULL DEFAULT '[]', body TEXT NOT NULL,
			PRIMARY KEY (ecosystem, name, id))`,
	} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("offline load: staging: %w", err)
		}
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO osv_affected_staging(id, ecosystem, name, versions_json, ranges_json, body) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ecosystem, name, id) DO UPDATE SET versions_json = excluded.versions_json, ranges_json = excluded.ranges_json, body = excluded.body`)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	l.stmt = stmt
	return l, nil
}

// Stage inserts one record into the staging table.
func (l *OfflineLoad) Stage(ctx context.Context, r AffectedRecord) error {
	if l.done {
		return ErrLoadFinished
	}
	if r.ID == "" || r.Ecosystem == "" || r.Name == "" {
		return errors.New("offline load: record missing id, ecosystem or name")
	}
	if r.VersionsJSON == "" {
		r.VersionsJSON = "[]"
	}
	if r.RangesJSON == "" {
		r.RangesJSON = "[]"
	}
	if _, err := l.stmt.ExecContext(ctx, r.ID, r.Ecosystem, r.Name, r.VersionsJSON, r.RangesJSON, string(r.Body)); err != nil {
		return err
	}
	l.rows++
	return nil
}

// Rows staged so far.
func (l *OfflineLoad) Rows() int64 { return l.rows }

// ReplaceKEV replaces the kev table inside the load transaction.
func (l *OfflineLoad) ReplaceKEV(ctx context.Context, entries []KEVEntry, version string) error {
	if l.done {
		return ErrLoadFinished
	}
	return replaceKEV(ctx, l.tx, entries, version)
}

// ReplaceEPSS replaces the epss table inside the load transaction.
func (l *OfflineLoad) ReplaceEPSS(ctx context.Context, entries []EPSSEntry, version string) error {
	if l.done {
		return ErrLoadFinished
	}
	return replaceEPSS(ctx, l.tx, entries, version)
}

// Commit swaps the staged rows into osv_affected, records the source
// version in vulndb_meta and commits. On any error the transaction is
// rolled back.
func (l *OfflineLoad) Commit(ctx context.Context, version string) error {
	if l.done {
		return ErrLoadFinished
	}
	l.done = true
	l.stmt.Close()
	defer l.tx.Rollback() // no-op after a successful Commit
	for _, q := range []string{
		`DELETE FROM osv_affected`,
		`INSERT INTO osv_affected(id, ecosystem, name, versions_json, ranges_json, body) SELECT id, ecosystem, name, versions_json, ranges_json, body FROM osv_affected_staging`,
		`DROP TABLE osv_affected_staging`,
	} {
		if _, err := l.tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("offline load: swap: %w", err)
		}
	}
	if err := setMeta(ctx, l.tx, SourceOSVOffline, version); err != nil {
		return err
	}
	return l.tx.Commit()
}

// Rollback abandons the load; nothing is changed.
func (l *OfflineLoad) Rollback() error {
	if l.done {
		return nil
	}
	l.done = true
	l.stmt.Close()
	return l.tx.Rollback()
}
