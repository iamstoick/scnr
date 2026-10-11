package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
)

type fakeEngine struct {
	name string
	run  func(ctx context.Context, emit EmitFunc) error
}

func (f *fakeEngine) Name() string                { return f.name }
func (f *fakeEngine) Supports(domain.Target) bool { return true }
func (f *fakeEngine) Plan(context.Context, domain.Target, Options) (Plan, error) {
	return Plan{Summary: f.name}, nil
}
func (f *fakeEngine) Run(ctx context.Context, _ domain.Target, _ Options, emit EmitFunc) error {
	return f.run(ctx, emit)
}

func TestRunnerStatusesAndBoundedParallelism(t *testing.T) {
	var active, maxActive int32
	slow := func(ctx context.Context, emit EmitFunc) error {
		n := atomic.AddInt32(&active, 1)
		for {
			m := atomic.LoadInt32(&maxActive)
			if n <= m || atomic.CompareAndSwapInt32(&maxActive, m, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return emit(domain.Finding{RuleID: "x"})
	}
	engines := []Engine{
		&fakeEngine{"a", slow}, &fakeEngine{"b", slow}, &fakeEngine{"c", slow},
		&fakeEngine{"skip", func(context.Context, EmitFunc) error { return &SkipError{Reason: "offline"} }},
		&fakeEngine{"partial", func(_ context.Context, emit EmitFunc) error {
			emit(domain.Finding{RuleID: "y"})
			return &PartialError{Reason: "ranges"}
		}},
		&fakeEngine{"fail", func(context.Context, EmitFunc) error { return errors.New("boom") }},
		&fakeEngine{"panic", func(context.Context, EmitFunc) error { panic("oops") }},
		&fakeEngine{"timeout", func(ctx context.Context, _ EmitFunc) error { <-ctx.Done(); return ctx.Err() }},
	}
	var emitted int32
	r := &Runner{}
	runs, err := r.Run(context.Background(), engines, domain.Target{}, Options{Profile: Profile{MaxParallelEngines: 2, EngineTimeout: 50 * time.Millisecond}}, func(f domain.Finding) error {
		if f.Engine == "" {
			t.Error("runner must stamp Engine")
		}
		atomic.AddInt32(&emitted, 1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if maxActive > 2 {
		t.Fatalf("parallelism %d exceeded 2", maxActive)
	}
	if emitted != 4 {
		t.Fatalf("emitted %d", emitted)
	}
	byName := map[string]domain.EngineRun{}
	for _, r := range runs {
		byName[r.Name] = r
	}
	if byName["a"].Status != "ok" || byName["skip"].Status != "skipped: offline" || byName["fail"].Status != "failed" || byName["fail"].Error != "boom" {
		t.Fatalf("%+v", byName)
	}
	if byName["panic"].Status != "failed" || byName["timeout"].Status != "failed" || byName["timeout"].Error == "" {
		t.Fatalf("%+v %+v", byName["panic"], byName["timeout"])
	}
	// A PartialError keeps the engine's findings and marks the run partial,
	// neither ok nor failed.
	if byName["partial"].Status != "partial: ranges" || byName["partial"].Error != "" {
		t.Fatalf("%+v", byName["partial"])
	}
	partial, allFailed := Summarise(runs)
	if !partial || allFailed {
		t.Fatal("summarise")
	}
	if p, af := Summarise([]domain.EngineRun{{Status: "failed"}}); !p || !af {
		t.Fatal("all failed")
	}
	if p, _ := Summarise([]domain.EngineRun{{Status: "ok"}}); p {
		t.Fatal("ok is not partial")
	}
}

// Finding 2: an engine that ignores its context cannot block the scan past
// EngineTimeout + grace; it is marked failed and its late findings are
// refused, while other engines complete normally.
func TestRunnerAbandonsWedgedEngine(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var lateEmit error
	var lateDone = make(chan struct{})
	wedged := &fakeEngine{"wedged", func(_ context.Context, emit EmitFunc) error {
		<-release // ignores ctx entirely
		lateEmit = emit(domain.Finding{RuleID: "late"})
		close(lateDone)
		return nil
	}}
	fine := &fakeEngine{"fine", func(_ context.Context, emit EmitFunc) error { return emit(domain.Finding{RuleID: "x"}) }}
	var emitted int32
	r := &Runner{AbandonGrace: 20 * time.Millisecond}
	start := time.Now()
	runs, err := r.Run(context.Background(), []Engine{wedged, fine}, domain.Target{}, Options{Profile: Profile{MaxParallelEngines: 2, EngineTimeout: 50 * time.Millisecond}}, func(domain.Finding) error {
		atomic.AddInt32(&emitted, 1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Run blocked for %s on a wedged engine", took)
	}
	byName := map[string]domain.EngineRun{}
	for _, r := range runs {
		byName[r.Name] = r
	}
	if byName["fine"].Status != "ok" || emitted != 1 {
		t.Fatalf("%+v emitted=%d", byName["fine"], emitted)
	}
	if w := byName["wedged"]; w.Status != "failed" || !strings.Contains(w.Error, "timed out") || !strings.Contains(w.Error, "abandoned") {
		t.Fatalf("%+v", w)
	}
	release <- struct{}{}
	<-lateDone
	if !errors.Is(lateEmit, ErrAbandoned) || emitted != 1 {
		t.Fatalf("late finding accepted: err=%v emitted=%d", lateEmit, emitted)
	}
	if p, _ := Summarise(runs); !p {
		t.Fatal("abandoned engine must mark the scan partial")
	}
}

func TestRegistrySelect(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&fakeEngine{name: "netscan"})
	reg.Register(&fakeEngine{name: "sca"})
	reg.Register(&fakeEngine{name: "other"})
	quick, _ := ProfileByName("quick")
	got, err := reg.Select(domain.Target{}, quick, nil, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("quick profile should restrict engines: %v %v", got, err)
	}
	std, _ := ProfileByName("standard")
	got, _ = reg.Select(domain.Target{}, std, nil, []string{"sca"})
	if len(got) != 2 || got[0].Name() != "netscan" || got[1].Name() != "other" {
		t.Fatalf("skip: %v", names(got))
	}
	got, _ = reg.Select(domain.Target{}, std, []string{"sca"}, nil)
	if len(got) != 1 {
		t.Fatalf("only: %v", names(got))
	}
	if _, err := reg.Select(domain.Target{}, std, []string{"nope"}, nil); err == nil {
		t.Fatal("unknown engine accepted")
	}
	if _, err := ProfileByName("turbo"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate register must panic")
		}
	}()
	reg.Register(&fakeEngine{name: "sca"})
}

func names(es []Engine) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestWalkFiles(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o755)
	os.MkdirAll(filepath.Join(dir, "src", "ignored"), 0o755)
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("# c\n*.log\n/build/\nsrc/ignored/\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.log"), []byte("b"), 0o600)
	os.WriteFile(filepath.Join(dir, "src", "ignored", "c.txt"), []byte("c"), 0o600)
	os.WriteFile(filepath.Join(dir, "node_modules", "x", "d.js"), []byte("d"), 0o600)
	os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref"), 0o600)
	os.WriteFile(filepath.Join(dir, "bin"), []byte{0, 1, 2, 3}, 0o600)
	big := make([]byte, MaxFileBytes+1)
	os.WriteFile(filepath.Join(dir, "big"), big, 0o600)
	os.Symlink(filepath.Join(dir, "a.txt"), filepath.Join(dir, "link"))
	var seen []string
	st, err := WalkFiles(context.Background(), dir, func(rel string, _ []byte) error { seen = append(seen, rel); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != ".gitignore" || seen[1] != "a.txt" {
		t.Fatalf("seen %v", seen)
	}
	if st.Files != 2 || st.SkippedBig != 1 || st.SkippedBin != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestLoadRulesValidation(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "rules"), 0o755)
	write := func(body string) error {
		os.WriteFile(filepath.Join(dir, "rules", "r.yaml"), []byte(body), 0o600)
		_, err := LoadRules(os.DirFS(dir), "rules", "e")
		return err
	}
	good := "id: e.ok\nengine: e\ntitle: t\nseverity: high\nwhat: w\nwhy: y\nfix: f\nsafety: safe\n"
	if err := write(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"unknown field": good + "bogus: 1\n",
		"bad safety":    "id: e.ok\nengine: e\ntitle: t\nseverity: high\nwhat: w\nwhy: y\nfix: f\nsafety: destructive\n",
		"bad severity":  "id: e.ok\nengine: e\ntitle: t\nseverity: urgent\nwhat: w\nwhy: y\nfix: f\nsafety: safe\n",
		"bad id":        "id: Bad ID\nengine: e\ntitle: t\nseverity: high\nwhat: w\nwhy: y\nfix: f\nsafety: safe\n",
		"wrong engine":  "id: e.ok\nengine: other\ntitle: t\nseverity: high\nwhat: w\nwhy: y\nfix: f\nsafety: safe\n",
		"missing prose": "id: e.ok\nengine: e\ntitle: t\nseverity: high\nsafety: safe\n",
		"duplicate":     good + "---\n" + good,
	} {
		if err := write(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
