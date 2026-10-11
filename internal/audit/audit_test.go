package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/store"
)

func TestLogWritesStoreAndMirror(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mirror := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := New(s, mirror)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := w.Log(ctx, ActionScan, "scan1", map[string]any{"exit_code": 0}); err != nil {
		t.Fatal(err)
	}
	if err := w.Log(ctx, ActionGateRefused, "", map[string]any{"target": "x"}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	rows, _ := s.ListAudit(ctx, "", 10)
	if len(rows) != 2 || rows[1].Action != ActionScan || rows[1].ScanID != "scan1" || rows[1].Actor != Actor() {
		t.Fatalf("%+v", rows)
	}
	b, _ := os.ReadFile(mirror)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("mirror lines: %q", b)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["action"] != ActionScan || first["scan_id"] != "scan1" {
		t.Fatalf("%v %v", first, err)
	}
	info, _ := os.Stat(mirror)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mirror perm %v", info.Mode().Perm())
	}
	if _, err := New(s, filepath.Join(t.TempDir(), "missing", "x.jsonl")); err == nil {
		t.Fatal("unwritable mirror path accepted")
	}
}
