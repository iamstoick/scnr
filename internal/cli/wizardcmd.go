package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/wizard"
)

// runWizard launches the interactive flow (TTY only).
func (a *App) runWizard(ctx context.Context) error {
	if !a.IsTTY {
		return exitf(ExitUsage, "no target given and not running in a terminal.\nUsage: scnr scan TARGET [--ack-authorized --non-interactive]\nRun `scnr --help` for the full command list.")
	}
	if err := a.Open(ctx); err != nil {
		return err
	}
	reg, _, err := a.engineRegistry()
	if err != nil {
		return err
	}
	det := a.Detector()
	deps := wizard.Deps{
		Out:          a.Stdout,
		Acknowledged: a.Config != nil && a.Config.Authorization.Acknowledged,
		Detect: func(ctx context.Context, raw string) (domain.Target, error) {
			return det.Detect(ctx, raw, "")
		},
		Plan: func(ctx context.Context, t domain.Target, profile string) ([]string, error) {
			p, err := engine.ProfileByName(profile)
			if err != nil {
				return nil, err
			}
			engs, err := reg.Select(t, p, nil, nil)
			if err != nil {
				return nil, err
			}
			limits, _, _ := safety.NewLimits(t.Public, safety.LimitRequest{})
			var lines []string
			for _, e := range engs {
				pl, err := e.Plan(ctx, t, engine.Options{Profile: p, Limiter: limits, Online: true})
				if err != nil {
					continue
				}
				lines = append(lines, e.Name()+": "+pl.Summary)
			}
			return lines, nil
		},
		SCAApplies: func(t domain.Target) bool { return t.Type == domain.TargetPath },
	}
	req, err := wizard.Run(ctx, deps)
	if err != nil {
		if errors.Is(err, wizard.ErrCancelled) {
			return exitf(ExitUsage, "cancelled")
		}
		return err
	}
	scan, code, err := a.RunScan(ctx, req)
	if err != nil {
		return &ExitError{Code: code, Err: err}
	}
	if scan != nil {
		fmt.Fprintf(a.Stdout, "\nNext time: %s\n", req.Flags())
	}
	if code != ExitOK {
		return &ExitError{Code: code}
	}
	return nil
}
