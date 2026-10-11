package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
)

// This file holds the vulnerability-management queries: scan diff, the
// open/fixed lifecycle, accept-risk suppressions with expiry, and baselines.
// All statements are parameterised; IN lists are built from "?" placeholders.

// MaxSuppressionDays caps --expires.
const MaxSuppressionDays = 365

// PreviousScan returns the most recent finished scan with the same target
// set before excludeID; ok=false when none exists.
func (s *Store) PreviousScan(ctx context.Context, targetSetHash, excludeID string) (string, bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM scans WHERE target_set_hash = ? AND id != ? AND finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 1`, targetSetHash, excludeID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}

// Diff is the fingerprint-level comparison of two scans.
type Diff struct {
	New       []string // in B, not in A
	Fixed     []string // in A, not in B
	Unchanged int
}

// DiffScans compares the occurrence sets of scans a and b.
func (s *Store) DiffScans(ctx context.Context, a, b string) (*Diff, error) {
	for _, id := range []string{a, b} {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE id = ?`, id).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, fmt.Errorf("scan %q: %w", id, ErrNotFound)
		}
	}
	d := &Diff{}
	var err error
	if d.New, err = s.fingerprintsOnlyIn(ctx, b, a); err != nil {
		return nil, err
	}
	if d.Fixed, err = s.fingerprintsOnlyIn(ctx, a, b); err != nil {
		return nil, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_occurrences x WHERE x.scan_id = ? AND x.fingerprint IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?)`, a, b).Scan(&d.Unchanged)
	return d, err
}

func (s *Store) fingerprintsOnlyIn(ctx context.Context, in, notIn string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.fingerprint FROM finding_occurrences o JOIN findings f ON f.fingerprint = o.fingerprint
		WHERE o.scan_id = ? AND o.fingerprint NOT IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?) ORDER BY f.risk DESC, o.fingerprint`, in, notIn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// MarkFixed sets status=fixed on open findings that were seen in an earlier
// scan of the same target set as scanID but not in scanID, restricted to
// findings whose engine is in okEngines: the engines that completed
// successfully in scanID. A finding whose engine was skipped, failed,
// timed out or was not selected (--engines, --skip-engines) is left open,
// because its absence proves nothing; it is marked fixed by the next scan
// in which its engine runs clean. Accepted and suppressed findings keep
// their status until expiry or revocation. Returns the number of findings
// marked; zero when okEngines is empty.
func (s *Store) MarkFixed(ctx context.Context, scanID string, okEngines []string) (int, error) {
	if len(okEngines) == 0 {
		return 0, nil
	}
	ph := make([]string, len(okEngines))
	args := []any{scanID, scanID, scanID}
	for i, e := range okEngines {
		ph[i] = "?"
		args = append(args, e)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE findings SET status = 'fixed' WHERE status = 'open'
		AND fingerprint IN (SELECT o.fingerprint FROM finding_occurrences o JOIN scans sc ON sc.id = o.scan_id
			WHERE sc.id != ? AND sc.target_set_hash = (SELECT target_set_hash FROM scans WHERE id = ?))
		AND fingerprint NOT IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?)
		AND engine IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RiskRow is the minimal per-finding data needed for posture and policy.
type RiskRow struct {
	Fingerprint string
	Risk        int
	Severity    domain.Severity
	Status      domain.Status
	KEV         bool
}

// ScanRiskRows streams (risk, status, kev) for every finding seen in a
// scan, after suppressions and baselines have been applied, so posture and
// policy reflect the stored status rather than the engine's emission.
func (s *Store) ScanRiskRows(ctx context.Context, scanID string, fn func(RiskRow)) error {
	rows, err := s.db.QueryContext(ctx, `SELECT f.fingerprint, f.risk, f.severity, f.status, f.kev FROM findings f JOIN finding_occurrences o ON o.fingerprint = f.fingerprint WHERE o.scan_id = ?`, scanID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r RiskRow
		var sev, kev int
		var status string
		if err := rows.Scan(&r.Fingerprint, &r.Risk, &sev, &status, &kev); err != nil {
			return err
		}
		r.Severity, r.Status, r.KEV = domain.Severity(sev), domain.Status(status), kev == 1
		fn(r)
	}
	return rows.Err()
}

// ---- suppressions (accept-risk) ----

// Suppression is an accepted risk, by fingerprint or by rule (optionally
// scoped to an asset), with a mandatory reason and expiry.
type Suppression struct {
	ID          string
	Fingerprint string
	RuleID      string
	AssetKey    string
	Reason      string
	CreatedBy   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   time.Time // zero when active
}

// Active reports whether the suppression applies at time now.
func (sp Suppression) Active(now time.Time) bool {
	return sp.RevokedAt.IsZero() && now.Before(sp.ExpiresAt)
}

// AddSuppression validates and stores an accept-risk record and marks
// currently matching open findings accepted. Reason and expiry are
// mandatory; expiry is capped at MaxSuppressionDays.
func (s *Store) AddSuppression(ctx context.Context, sp Suppression) (Suppression, int, error) {
	if strings.TrimSpace(sp.Reason) == "" {
		return sp, 0, errors.New("accept: --reason is required")
	}
	if sp.Fingerprint == "" && sp.RuleID == "" {
		return sp, 0, errors.New("accept: a fingerprint or rule ID is required")
	}
	if sp.CreatedAt.IsZero() {
		sp.CreatedAt = time.Now()
	}
	if sp.ExpiresAt.IsZero() || !sp.ExpiresAt.After(sp.CreatedAt) {
		return sp, 0, errors.New("accept: --expires is required and must be in the future")
	}
	if sp.ExpiresAt.Sub(sp.CreatedAt) > MaxSuppressionDays*24*time.Hour {
		return sp, 0, fmt.Errorf("accept: --expires may not exceed %d days", MaxSuppressionDays)
	}
	if sp.ID == "" {
		sp.ID = domain.NewID()
	}
	var applied int
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var fp, rule, asset any
		if sp.Fingerprint != "" {
			fp = sp.Fingerprint
		}
		if sp.RuleID != "" {
			rule = sp.RuleID
		}
		if sp.AssetKey != "" {
			asset = sp.AssetKey
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO suppressions(id, fingerprint, rule_id, asset_key, reason, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sp.ID, fp, rule, asset, sp.Reason, sp.CreatedBy, fmtTime(sp.CreatedAt), fmtTime(sp.ExpiresAt)); err != nil {
			return err
		}
		n, err := setStatusMatching(ctx, tx, sp, domain.StatusAccepted, []domain.Status{domain.StatusOpen}, "")
		applied = n
		return err
	})
	return sp, applied, err
}

// setStatusMatching updates findings matching a suppression (by fingerprint,
// or by rule optionally scoped to an asset and to one scan) from any of the
// `from` statuses to `to`.
func setStatusMatching(ctx context.Context, tx *sql.Tx, sp Suppression, to domain.Status, from []domain.Status, scanID string) (int, error) {
	var where []string
	args := []any{string(to)}
	fromPh := make([]string, len(from))
	for i, f := range from {
		fromPh[i] = "?"
		args = append(args, string(f))
	}
	where = append(where, `status IN (`+strings.Join(fromPh, ",")+`)`)
	if sp.Fingerprint != "" {
		where = append(where, `fingerprint = ?`)
		args = append(args, sp.Fingerprint)
	} else {
		where = append(where, `rule_id = ?`)
		args = append(args, sp.RuleID)
		if sp.AssetKey != "" {
			where = append(where, `asset_id IN (SELECT id FROM assets WHERE key = ?)`)
			args = append(args, sp.AssetKey)
		}
	}
	if scanID != "" {
		where = append(where, `fingerprint IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?)`)
		args = append(args, scanID)
	}
	res, err := tx.ExecContext(ctx, `UPDATE findings SET status = ? WHERE `+strings.Join(where, " AND "), args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListSuppressions returns suppressions, newest first; revoked ones only
// when includeRevoked is set.
func (s *Store) ListSuppressions(ctx context.Context, includeRevoked bool, limit int) ([]Suppression, error) {
	if limit <= 0 {
		limit = 50
	}
	q := suppressionColumns
	if !includeRevoked {
		q += ` WHERE revoked_at IS NULL`
	}
	return s.querySuppressions(ctx, q+` ORDER BY created_at DESC LIMIT ?`, limit)
}

const suppressionColumns = `SELECT id, COALESCE(fingerprint,''), COALESCE(rule_id,''), COALESCE(asset_key,''), reason, created_by, created_at, expires_at, COALESCE(revoked_at,'') FROM suppressions`

func (s *Store) querySuppressions(ctx context.Context, q string, args ...any) ([]Suppression, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Suppression
	for rows.Next() {
		sp, err := scanSuppression(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

func scanSuppression(rows interface{ Scan(...any) error }) (Suppression, error) {
	var sp Suppression
	var created, expires, revoked string
	if err := rows.Scan(&sp.ID, &sp.Fingerprint, &sp.RuleID, &sp.AssetKey, &sp.Reason, &sp.CreatedBy, &created, &expires, &revoked); err != nil {
		return sp, err
	}
	sp.CreatedAt, sp.ExpiresAt = parseTime(created), parseTime(expires)
	if revoked != "" {
		sp.RevokedAt = parseTime(revoked)
	}
	return sp, nil
}

// GetSuppression loads one by ID (or unique ID prefix of >= 8 chars).
func (s *Store) GetSuppression(ctx context.Context, id string) (*Suppression, error) {
	if len(id) < 8 {
		return nil, fmt.Errorf("suppression id %q too short", id)
	}
	out, err := s.querySuppressions(ctx, suppressionColumns+` WHERE id = ? OR (length(?) < 32 AND substr(id, 1, length(?)) = ?) LIMIT 2`, id, id, id, id)
	if err != nil {
		return nil, err
	}
	switch len(out) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return &out[0], nil
	}
	return nil, fmt.Errorf("suppression id prefix %q is ambiguous", id)
}

// RevokeSuppression marks a suppression revoked and reopens findings it
// had accepted. Returns the number of findings reopened.
func (s *Store) RevokeSuppression(ctx context.Context, id string) (*Suppression, int, error) {
	sp, err := s.GetSuppression(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	if !sp.RevokedAt.IsZero() {
		return sp, 0, errors.New("suppression already revoked")
	}
	var reopened int
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE suppressions SET revoked_at = ? WHERE id = ?`, now(), sp.ID); err != nil {
			return err
		}
		n, err := setStatusMatching(ctx, tx, *sp, domain.StatusOpen, []domain.Status{domain.StatusAccepted}, "")
		reopened = n
		return err
	})
	if err == nil {
		sp.RevokedAt = time.Now()
	}
	return sp, reopened, err
}

// Reverted describes an expired acceptance whose findings went back to open.
type Reverted struct {
	Suppression Suppression
	Reopened    int
}

// ApplySuppressions runs the lifecycle for one scan: expired acceptances
// revert their findings to open (reported so the caller can audit them),
// then active acceptances mark matching open findings in this scan accepted.
func (s *Store) ApplySuppressions(ctx context.Context, scanID string, now time.Time) (applied int, reverted []Reverted, err error) {
	all, err := s.ListSuppressions(ctx, false, 100000)
	if err != nil {
		return 0, nil, err
	}
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		for _, sp := range all {
			if sp.Active(now) {
				continue
			}
			n, err := setStatusMatching(ctx, tx, sp, domain.StatusOpen, []domain.Status{domain.StatusAccepted}, "")
			if err != nil {
				return err
			}
			if n > 0 {
				reverted = append(reverted, Reverted{Suppression: sp, Reopened: n})
			}
		}
		for _, sp := range all {
			if !sp.Active(now) {
				continue
			}
			n, err := setStatusMatching(ctx, tx, sp, domain.StatusAccepted, []domain.Status{domain.StatusOpen}, scanID)
			if err != nil {
				return err
			}
			applied += n
		}
		return nil
	})
	return applied, reverted, err
}

// ---- baseline ----

const inChunk = 500

// ApplyBaseline marks open findings of the scan that match the baseline
// (fingerprints or rule IDs) suppressed, and reopens findings in the scan
// that were suppressed by an earlier baseline but match this one no longer
// (a baseline must be supplied on every scan; it has no expiry).
func (s *Store) ApplyBaseline(ctx context.Context, scanID string, fingerprints, ruleIDs []string) (suppressed, reopened int, err error) {
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'open' WHERE status = 'suppressed' AND fingerprint IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?)`, scanID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		reopened = int(n)
		for _, chunk := range chunks(fingerprints, inChunk) {
			n, err := updateIn(ctx, tx, `UPDATE findings SET status = 'suppressed' WHERE status = 'open' AND fingerprint IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?) AND fingerprint IN (`, scanID, chunk)
			if err != nil {
				return err
			}
			suppressed += n
		}
		for _, chunk := range chunks(ruleIDs, inChunk) {
			n, err := updateIn(ctx, tx, `UPDATE findings SET status = 'suppressed' WHERE status = 'open' AND fingerprint IN (SELECT fingerprint FROM finding_occurrences WHERE scan_id = ?) AND rule_id IN (`, scanID, chunk)
			if err != nil {
				return err
			}
			suppressed += n
		}
		return nil
	})
	// Findings reopened then re-suppressed by the same baseline are not a change.
	if reopened > suppressed {
		reopened -= suppressed
	} else {
		reopened = 0
	}
	return suppressed, reopened, err
}

func updateIn(ctx context.Context, tx *sql.Tx, prefix, scanID string, values []string) (int, error) {
	ph := make([]string, len(values))
	args := make([]any, 0, len(values)+1)
	args = append(args, scanID)
	for i, v := range values {
		ph[i] = "?"
		args = append(args, v)
	}
	res, err := tx.ExecContext(ctx, prefix+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func chunks(vals []string, n int) [][]string {
	var out [][]string
	for len(vals) > 0 {
		k := n
		if len(vals) < k {
			k = len(vals)
		}
		out = append(out, vals[:k])
		vals = vals[k:]
	}
	return out
}

// ScanFingerprintsAndRules returns the fingerprints and distinct rule IDs
// seen in a scan (for `baseline create`).
func (s *Store) ScanFingerprintsAndRules(ctx context.Context, scanID string) (fps, rules []string, err error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.fingerprint, f.rule_id FROM findings f JOIN finding_occurrences o ON o.fingerprint = f.fingerprint WHERE o.scan_id = ? ORDER BY f.rule_id, f.fingerprint`, scanID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var fp, rule string
		if err := rows.Scan(&fp, &rule); err != nil {
			return nil, nil, err
		}
		fps = append(fps, fp)
		if !seen[rule] {
			seen[rule] = true
			rules = append(rules, rule)
		}
	}
	return fps, rules, rows.Err()
}
