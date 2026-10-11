package store

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
)

// BatchSize is the number of findings written per transaction.
const BatchSize = 500

// Writer is the single writer goroutine for a scan's findings. Engines call
// Add from any goroutine; findings are buffered on a channel and flushed in
// batches so nothing accumulates in memory.
type Writer struct {
	s        *Store
	scanID   string
	ch       chan domain.Finding
	done     chan struct{}
	err      error
	mu       sync.Mutex
	count    int
	assets   map[string]string // asset key -> id
	isPublic func(assetKey string) bool
	closed   bool
}

// NewWriter starts the writer goroutine. isPublic tells the writer whether
// an asset key (including hosts discovered mid-scan) is internet-facing.
func (s *Store) NewWriter(ctx context.Context, scanID string, isPublic func(assetKey string) bool) *Writer {
	w := &Writer{
		s:        s,
		scanID:   scanID,
		ch:       make(chan domain.Finding, BatchSize*2),
		done:     make(chan struct{}),
		assets:   map[string]string{},
		isPublic: isPublic,
	}
	if w.isPublic == nil {
		w.isPublic = func(string) bool { return false }
	}
	go w.loop(ctx)
	return w
}

// Add enqueues a finding. It blocks when the buffer is full (backpressure)
// and returns the writer's sticky error if a previous batch failed.
func (w *Writer) Add(f domain.Finding) error {
	w.mu.Lock()
	closed, err := w.closed, w.err
	w.mu.Unlock()
	if err != nil {
		return err
	}
	if closed {
		return fmt.Errorf("writer closed")
	}
	w.ch <- f
	return nil
}

// Close flushes and waits. It is safe to call once.
func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return w.err
	}
	w.closed = true
	w.mu.Unlock()
	close(w.ch)
	<-w.done
	return w.err
}

// Count returns how many findings were persisted.
func (w *Writer) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

func (w *Writer) setErr(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}

func (w *Writer) loop(ctx context.Context) {
	defer close(w.done)
	batch := make([]domain.Finding, 0, BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := w.writeBatch(ctx, batch); err != nil {
			w.setErr(err)
		}
		batch = batch[:0]
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case f, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, f)
			if len(batch) >= BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *Writer) writeBatch(ctx context.Context, batch []domain.Finding) error {
	err := w.s.withTx(ctx, func(tx *sql.Tx) error {
		for i := range batch {
			if err := w.writeOne(ctx, tx, &batch[i]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.count += len(batch)
	w.mu.Unlock()
	return nil
}

func (w *Writer) assetID(ctx context.Context, tx *sql.Tx, f *domain.Finding) (string, error) {
	if id, ok := w.assets[f.AssetKey]; ok {
		return id, nil
	}
	typ := domain.TargetHost
	name := f.AssetKey
	for _, p := range []struct {
		prefix string
		t      domain.TargetType
	}{{"url:", domain.TargetURL}, {"repo:", domain.TargetPath}, {"image:", domain.TargetImage}, {"aws:", domain.TargetCloud}, {"host:", domain.TargetHost}} {
		if len(f.AssetKey) > len(p.prefix) && f.AssetKey[:len(p.prefix)] == p.prefix {
			typ = p.t
			name = f.AssetKey[len(p.prefix):]
			break
		}
	}
	id, err := upsertAsset(ctx, tx, domain.Asset{Key: f.AssetKey, Type: typ, Name: name, Public: w.isPublic(f.AssetKey)})
	if err != nil {
		return "", err
	}
	w.assets[f.AssetKey] = id
	return id, nil
}

func (w *Writer) writeOne(ctx context.Context, tx *sql.Tx, f *domain.Finding) error {
	assetID, err := w.assetID(ctx, tx, f)
	if err != nil {
		return err
	}
	if f.Fingerprint == "" {
		f.Fingerprint = domain.Fingerprint(f.RuleID, f.AssetKey, f.Location)
	}
	ts := time.Now()
	if !f.LastSeen.IsZero() {
		ts = f.LastSeen
	}
	tss := fmtTime(ts)
	status := f.Status
	if status == "" {
		status = domain.StatusOpen
	}
	var vec, cvss, epss any
	if f.CVSS != nil {
		vec, cvss = f.CVSS.Vector, f.CVSS.Score
	}
	if f.EPSS != nil {
		epss = *f.EPSS
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO findings(fingerprint, asset_id, rule_id, engine, title, severity, confidence, what, why, fix, location, cves, cwe,
		cvss_vector, cvss_score, epss, kev, risk, refs, status, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen, risk = excluded.risk, severity = excluded.severity,
		  epss = excluded.epss, kev = excluded.kev, title = excluded.title, fix = excluded.fix,
		  status = CASE WHEN findings.status IN ('accepted','suppressed') THEN findings.status ELSE 'open' END`,
		f.Fingerprint, assetID, f.RuleID, f.Engine, f.Title, int(f.Severity), int(f.Confidence), f.WhatItIs, f.WhyItMatters, f.HowToFix, f.Location,
		marshalJSON(nonNil(f.CVEs)), f.CWE, vec, cvss, epss, boolInt(f.KEV), f.Risk, marshalJSON(nonNil(f.References)), string(status), tss, tss)
	if err != nil {
		return fmt.Errorf("insert finding %s: %w", f.RuleID, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_occurrences(scan_id, fingerprint, seen_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, w.scanID, f.Fingerprint, tss); err != nil {
		return err
	}
	for i, e := range f.Evidence {
		if i >= domain.MaxEvidencePerFinding {
			break
		}
		red := e.Redacted
		if len(red) > domain.MaxEvidenceBytes {
			red = red[:domain.MaxEvidenceBytes]
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence(fingerprint, scan_id, kind, location, redacted, hash) VALUES (?, ?, ?, ?, ?, ?)`,
			f.Fingerprint, w.scanID, e.Kind, e.Location, red, e.Hash); err != nil {
			return err
		}
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
