package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/report"
	"github.com/iamstoick/scnr/internal/safety"
	"github.com/iamstoick/scnr/internal/sched"
	"github.com/iamstoick/scnr/internal/target"
	"github.com/iamstoick/scnr/internal/wizard"
)

func (a *App) daemonCmd() *cobra.Command {
	var once bool
	var notifyURL, out string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run scheduled scans unattended",
	}
	run := &cobra.Command{
		Use:     "run",
		Short:   "Hold the lock and run due schedules until interrupted (--once: serve due rows once)",
		Example: "  scnr daemon run --notify-url https://relay.internal/scnr\n  scnr daemon run --once",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			var nb *sched.Notifier
			if notifyURL != "" {
				var err error
				nb, err = sched.NewNotifier(notifyURL, a.Log)
				if err != nil {
					return err
				}
			}
			d := &sched.Daemon{
				Store: a.Store, Audit: a.Audit,
				Parse: a.parseScheduleArgs,
				Scan: func(ctx context.Context, req wizard.ScanRequest) (sched.RunOutcome, error) {
					return a.runScheduled(ctx, req, out)
				},
				Lock: sched.SystemLocker, Notify: nb,
				Home: a.Home, Out: a.Stdout, Once: once,
			}
			if err := d.Run(cmd.Context()); err != nil {
				var locked *sched.LockedError
				if errors.As(err, &locked) {
					return &ExitError{Code: ExitUsage, Err: fmt.Errorf("daemon %s", locked.Error())}
				}
				if errors.Is(err, sched.ErrUnsupported) {
					return &ExitError{Code: ExitUsage, Err: err}
				}
				return err
			}
			return nil
		},
	}
	run.Flags().BoolVar(&once, "once", false, "serve every due schedule once and exit")
	run.Flags().StringVar(&notifyURL, "notify-url", "", "POST run summaries to this webhook (https, or http to loopback)")
	run.Flags().StringVar(&out, "out", "./scnr-out", "report directory when the stored argv sets no --out")
	cmd.AddCommand(run)
	return cmd
}

// runScheduled executes one validated request the way the daemon runs
// every scan: reload the scope file (broken → skipped, audited, loop
// continues), force a non-terminal copy of the app, enforce the per-run
// timeout, and extract the outcome for status and notify.
func (a *App) runScheduled(ctx context.Context, req wizard.ScanRequest, daemonOut string) (sched.RunOutcome, error) {
	var out sched.RunOutcome
	a.Config = nil
	a.configErr = nil
	a.loadConfig()
	if a.configErr != nil {
		out.Status = "skipped: broken scope file: " + firstLine(a.configErr.Error())
		return out, nil
	}
	if req.Out == "" {
		req.Out = daemonOut
	}
	// The daemon never prompts and never touches the terminal: force a
	// non-terminal run even when the daemon itself was started on one.
	// (App holds a mutex, so save/restore instead of copying; the daemon
	// runs one scan at a time, so no other goroutine observes this.)
	wasTTY := a.IsTTY
	a.IsTTY = false
	defer func() { a.IsTTY = wasTTY }()
	timeout := runTimeout(ctx, a, req)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	scan, code, err := a.RunScan(runCtx, req)
	switch {
	case ctx.Err() != nil:
		out.Status = "interrupted"
	case runCtx.Err() == context.DeadlineExceeded:
		out.Status = "timeout"
	case err != nil:
		var refusal *safety.RefusalError
		if errors.As(err, &refusal) {
			out.Status = "refused: " + refusal.Code
		} else {
			out.Status = "failed: " + firstLine(err.Error())
		}
	case scan.Partial:
		out.Status = "partial"
	default:
		out.Status = "ok"
	}
	// Status embeds error text into the row: redact before it lands.
	out.Status = a.redact(out.Status)
	if scan != nil {
		out.ScanID = scan.ID
		out.Summary = summarizeRun(req, scan, code)
	}
	return out, nil
}

// runTimeout bounds one daemon run: profile EngineTimeout × selected
// engines + 10 minutes. Deep sets no per-engine timeout; the daemon uses
// the standard equivalent so a stuck engine cannot stall the loop.
func runTimeout(ctx context.Context, cp *App, req wizard.ScanRequest) time.Duration {
	profile, err := engine.ProfileByName(req.Profile)
	if err != nil {
		profile = engine.Profile{EngineTimeout: 10 * time.Minute}
	}
	perEngine := profile.EngineTimeout
	if perEngine <= 0 {
		perEngine = 10 * time.Minute
		if std, err := engine.ProfileByName("standard"); err == nil && std.EngineTimeout > 0 {
			perEngine = std.EngineTimeout
		}
	}
	engines := 0
	if engs, err := cp.engineRegistry(); err == nil {
		typ, terr := target.ParseType(req.Type)
		if terr == nil {
			det := cp.Detector()
			for _, raw := range req.Targets {
				t, err := det.Detect(ctx, raw, typ)
				if err != nil {
					continue // RunScan fails the run; nothing to bound
				}
				sel, err := engs.reg.Select(t, profile, req.Engines, req.SkipEngines)
				if err != nil {
					continue
				}
				engines += len(sel)
			}
		}
	}
	return time.Duration(engines)*perEngine + 10*time.Minute
}

// summarizeRun builds the notify payload from a finished scan. Targets
// are the redacted raws; report paths are reconstructed deterministically
// (out/<scan-id>/<file>) exactly as WriteAll writes them.
func summarizeRun(req wizard.ScanRequest, scan *domain.Scan, code int) sched.Summary {
	targets := make([]string, 0, len(scan.Targets))
	for _, t := range scan.Targets {
		targets = append(targets, t.Raw)
	}
	var paths []string
	if reporters, err := report.ParseFormats(req.Formats, report.Registry(report.Meta{})); err == nil {
		for _, r := range reporters {
			paths = append(paths, filepath.Join(req.Out, scan.ID, r.FileName()))
		}
	}
	counts := scan.Posture.Counts
	if counts == nil {
		counts = map[string]int{}
	}
	return sched.Summary{
		SchemaVersion: "1", Schedule: req.Schedule, ScanID: scan.ID,
		StartedAt:  scan.StartedAt.Format(time.RFC3339),
		FinishedAt: scan.FinishedAt.Format(time.RFC3339),
		Profile:    scan.Profile, Targets: targets,
		Score: scan.Posture.Score, Grade: scan.Posture.Grade, Counts: counts,
		Partial: scan.Partial, ExitCode: code, ReportPaths: paths,
	}
}
