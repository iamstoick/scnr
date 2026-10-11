package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/iamstoick/scnr/internal/domain"
)

// Progress is called when an engine starts and finishes.
type Progress func(engine string, run *domain.EngineRun)

// Runner executes engines against a target with bounded parallelism.
type Runner struct {
	Progress Progress
	// AbandonGrace overrides the default grace period (tests); zero means
	// AbandonGrace.
	AbandonGrace time.Duration
}

func (r *Runner) grace() time.Duration {
	if r.AbandonGrace > 0 {
		return r.AbandonGrace
	}
	return AbandonGrace
}

// Run executes each engine (parallelism = profile.MaxParallelEngines) and
// returns one EngineRun per engine. emit is called from multiple goroutines
// and must be safe for concurrent use. Engine failures are recorded, not
// returned; the only returned error is a cancelled context.
func (r *Runner) Run(ctx context.Context, engines []Engine, t domain.Target, o Options, emit EmitFunc) ([]domain.EngineRun, error) {
	par := o.Profile.MaxParallelEngines
	if par <= 0 {
		par = 1
	}
	sem := semaphore.NewWeighted(par)
	runs := make([]domain.EngineRun, len(engines))
	var wg sync.WaitGroup
	for i, e := range engines {
		if err := sem.Acquire(ctx, 1); err != nil {
			return runs, err
		}
		wg.Add(1)
		go func(i int, e Engine) {
			defer wg.Done()
			defer sem.Release(1)
			runs[i] = r.runOne(ctx, e, t, o, emit)
		}(i, e)
	}
	wg.Wait()
	return runs, ctx.Err()
}

// AbandonGrace is how long the Runner waits, after an engine's context is
// done, for Run to return on its own before the engine is abandoned.
const AbandonGrace = 2 * time.Second

// ErrAbandoned is returned to an abandoned engine's emit calls so a
// cooperative engine stops at its next finding.
var ErrAbandoned = errors.New("engine abandoned after timeout")

// engineResult is what the engine goroutine hands back.
type engineResult struct {
	err      error
	panicked bool
	panicVal any
}

// runOne executes one engine with its timeout. The engine runs in its own
// goroutine so a wedged engine that ignores ctx (a parser stuck in a hostile
// file, a tool that does not exit) cannot block the scan: when the context
// is done and Run has not returned within AbandonGrace the engine is
// marked failed and left behind. Trade-off: an abandoned goroutine leaks
// until it returns on its own; it is bounded to one per engine per scan,
// its emit calls are refused (ErrAbandoned) so it can produce nothing, and
// the process exits at the end of the scan anyway.
func (r *Runner) runOne(ctx context.Context, e Engine, t domain.Target, o Options, emit EmitFunc) (run domain.EngineRun) {
	run = domain.EngineRun{Name: e.Name(), Status: "running"}
	if r.Progress != nil {
		r.Progress(e.Name(), &run)
	}
	start := time.Now()
	var ectx context.Context
	var cancel context.CancelFunc
	if o.Profile.EngineTimeout > 0 {
		ectx, cancel = context.WithTimeout(ctx, o.Profile.EngineTimeout)
	} else {
		ectx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	defer func() {
		run.Duration = time.Since(start)
		if r.Progress != nil {
			r.Progress(e.Name(), &run)
		}
	}()
	var abandoned atomic.Bool
	done := make(chan engineResult, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- engineResult{panicked: true, panicVal: p}
			}
		}()
		err := e.Run(ectx, t, o, func(f domain.Finding) error {
			if abandoned.Load() {
				return ErrAbandoned
			}
			f.Engine = e.Name()
			return emit(f)
		})
		done <- engineResult{err: err}
	}()
	var res engineResult
	select {
	case res = <-done:
	case <-ectx.Done():
		select {
		case res = <-done:
		case <-time.After(r.grace()):
			abandoned.Store(true)
			run.Status = "failed"
			run.Error = timeoutMessage(ctx, o.Profile.EngineTimeout) + " (engine did not stop; abandoned)"
			return run
		}
	}
	if res.panicked {
		run.Status = "failed"
		run.Error = fmt.Sprintf("panic: %v", res.panicVal)
		return run
	}
	if v, ok := e.(Versioned); ok {
		run.Version = v.Version()
	}
	var skip *SkipError
	var partial *PartialError
	switch {
	case res.err == nil:
		run.Status = "ok"
	case errors.As(res.err, &skip):
		run.Status = "skipped: " + skip.Reason
	case errors.As(res.err, &partial):
		run.Status = "partial: " + partial.Reason
	case errors.Is(ectx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		run.Status = "failed"
		run.Error = timeoutMessage(ctx, o.Profile.EngineTimeout)
	default:
		run.Status = "failed"
		run.Error = res.err.Error()
	}
	return run
}

func timeoutMessage(ctx context.Context, timeout time.Duration) string {
	if ctx.Err() != nil {
		return "scan cancelled"
	}
	return "timed out after " + timeout.String()
}

// Summarise returns (partial, allFailed) over runs.
func Summarise(runs []domain.EngineRun) (partial, allFailed bool) {
	if len(runs) == 0 {
		return false, false
	}
	allFailed = true
	for _, r := range runs {
		if r.Status != "ok" {
			partial = true
		}
		if r.Status != "failed" {
			allFailed = false
		}
	}
	return partial, allFailed
}
