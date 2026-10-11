// Package audit writes append-only audit rows to the store and optionally
// mirrors them to a JSONL file.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"sync"
	"time"

	"github.com/iamstoick/scnr/internal/store"
)

// Actions recorded (Section 9).
const (
	ActionScan            = "scan"
	ActionGateRefused     = "gate_refused"
	ActionAccept          = "accept"
	ActionVerify          = "verify"
	ActionDBUpdate        = "db_update"
	ActionLimitOverride   = "limit_override"
	ActionScopeInit       = "scope_init"
	ActionMigrateDown     = "db_migrate_down"
	ActionAcceptRevoke    = "accept_revoke"
	ActionAcceptExpired   = "accept_expired"
	ActionBaseline        = "baseline"
	ActionPolicyCheck     = "policy_check"
	ActionSBOM            = "sbom"
	ActionKeygen          = "db_keygen"
	ActionBundleBuild     = "db_bundle_build"
	ActionBundleVerify    = "db_bundle_verify"
	ActionSchedule        = "schedule"
	ActionScheduleSkipped = "schedule_skipped"
)

// Writer appends audit entries.
type Writer struct {
	s     *store.Store
	actor string
	mu    sync.Mutex
	file  *os.File
}

// New returns an audit writer. jsonlPath may be empty.
func New(s *store.Store, jsonlPath string) (*Writer, error) {
	w := &Writer{s: s, actor: Actor()}
	if jsonlPath != "" {
		f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit file: %w", err)
		}
		w.file = f
	}
	return w, nil
}

// Actor returns the OS username (or "unknown").
func Actor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

// Close the mirror file.
func (w *Writer) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Log appends one row. detail is marshalled to JSON.
func (w *Writer) Log(ctx context.Context, action, scanID string, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	e := store.AuditEntry{TS: time.Now(), Actor: w.actor, Action: action, ScanID: scanID, Detail: b}
	id, err := w.s.AppendAudit(ctx, e)
	if err != nil {
		return err
	}
	if w.file != nil {
		w.mu.Lock()
		defer w.mu.Unlock()
		line, _ := json.Marshal(map[string]any{
			"id": id, "ts": e.TS.UTC().Format(time.RFC3339Nano), "actor": e.Actor, "action": e.Action, "scan_id": e.ScanID, "detail": json.RawMessage(b),
		})
		if _, err := w.file.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}
