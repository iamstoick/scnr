package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/doctor"
	cloudaws "github.com/iamstoick/scnr/internal/engine/cloud/aws"
	"github.com/iamstoick/scnr/internal/sched"
)

func (a *App) doctorCmd() *cobra.Command {
	var guide, online bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check config, database, vulnerability data and available tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			if guide {
				doctor.PrintInstallGuide(a.Stdout)
				return nil
			}
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			adapters, err := a.adapters()
			if err != nil {
				return err
			}
			detectors := map[string]doctor.Detector{}
			for _, ad := range adapters {
				detectors[ad.Binary()] = ad
			}
			opts := doctor.Options{Home: a.Home, ConfigPath: a.ConfigPath, Store: a.Store, Online: online, Adapters: detectors, Extra: append(a.cloudChecks(cmd.Context()), a.daemonChecks(cmd.Context())...)}
			if online {
				// Reachability probes go through the same endpoint-restricted
				// client as the real fetches (SAFETY.md item 9).
				if opts.HTTP, err = a.endpointClient(doctor.OutboundURLs()...); err != nil {
					return err
				}
			}
			checks, err := doctor.Run(cmd.Context(), opts)
			if err != nil {
				return err
			}
			doctor.Print(a.Stdout, checks)
			if online {
				fmt.Fprintln(a.Stdout, "\nOutbound hosts scnr may contact (never anything else):")
				for _, h := range doctor.ListsOutbound() {
					fmt.Fprintln(a.Stdout, "  -", h)
				}
				fmt.Fprintln(a.Stdout, "\nExternal tools contact these on their own when their adapters run:")
				for _, h := range doctor.ToolOutbound() {
					fmt.Fprintln(a.Stdout, "  -", h)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&guide, "install-guide", false, "print install commands for optional tools (never runs them)")
	cmd.Flags().BoolVar(&online, "online", false, "also check reachability of osv.dev and feed hosts")
	return cmd
}

// cloudChecks reports which AWS credential source a scan would use (files
// and env are read; nothing is called) and the account allowlist state.
func (a *App) cloudChecks(ctx context.Context) []doctor.Check {
	cfg := a.cloudConfig()
	var out []doctor.Check
	src, err := cloudaws.DescribeCredentialSource(ctx, "", cfg.InstanceCredentials)
	switch {
	case err != nil:
		out = append(out, doctor.Check{Name: "aws credentials", Status: doctor.Warn, Detail: a.redact(err.Error()) + " (aws:// scans need one; profiles: aws://<profile>)"})
	default:
		out = append(out, doctor.Check{Name: "aws credentials", Status: doctor.OK, Detail: "source " + src + " (not resolved; confirmed by sts:GetCallerIdentity at scan time)"})
	}
	switch {
	case len(cfg.Accounts) == 0:
		out = append(out, doctor.Check{Name: "aws accounts", Status: doctor.Warn, Detail: "cloud.aws.accounts is empty: aws:// scans need interactive confirmation of the account id and are refused with --non-interactive"})
	default:
		out = append(out, doctor.Check{Name: "aws accounts", Status: doctor.OK, Detail: fmt.Sprintf("%d allow-listed (%s)", len(cfg.Accounts), strings.Join(cfg.Accounts, ", "))})
	}
	if cfg.InstanceCredentials {
		out = append(out, doctor.Check{Name: "aws instance credentials", Status: doctor.Warn, Detail: "enabled: IMDS/ECS credential endpoints may be contacted (audited as limit_override)"})
	}
	return out
}

// daemonChecks reports the daemon lock state and the schedules due in the
// next 24 hours.
func (a *App) daemonChecks(ctx context.Context) []doctor.Check {
	running, pid := sched.LockState(a.Home)
	lock := doctor.Check{Name: "daemon", Status: doctor.OK, Detail: "not running"}
	if running {
		lock.Detail = fmt.Sprintf("running (pid %d)", pid)
	}
	out := []doctor.Check{lock}
	if a.Store == nil {
		return out
	}
	rows, err := a.Store.ListSchedules(ctx)
	if err != nil {
		return append(out, doctor.Check{Name: "schedules", Status: doctor.Warn, Detail: err.Error()})
	}
	horizon := time.Now().Add(24 * time.Hour)
	var due []string
	for _, s := range rows {
		if s.Enabled && !s.NextRun.After(horizon) {
			due = append(due, s.Name+" @ "+s.NextRun.Format(time.RFC3339))
		}
	}
	switch {
	case len(rows) == 0:
		out = append(out, doctor.Check{Name: "schedules", Status: doctor.OK, Detail: "none stored"})
	case len(due) == 0:
		out = append(out, doctor.Check{Name: "schedules", Status: doctor.OK, Detail: fmt.Sprintf("%d stored, none due in 24h", len(rows))})
	default:
		out = append(out, doctor.Check{Name: "schedules", Status: doctor.OK, Detail: fmt.Sprintf("%d due in 24h: %s", len(due), strings.Join(due, ", "))})
	}
	return out
}
