package cli

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/sched"
	"github.com/iamstoick/scnr/internal/store"
	"github.com/iamstoick/scnr/internal/wizard"
)

// scheduleRefusedReasons lists flags schedules never accept, with the
// reason shown. Presence-based and checked before dry-parsing, so the
// refusal survives these flags being added to scanCmd later (4d) and
// catches --flag=value forms.
var scheduleRefusedReasons = map[string]string{
	"ack-authorized":  "record authorization once with `scnr scope init`",
	"header":          "schedules cannot carry request headers",
	"cookie":          "schedules cannot carry cookies",
	"non-interactive": "the daemon already runs non-interactively",
}

func (a *App) scheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage scheduled scans run by the daemon",
	}
	cmd.AddCommand(a.scheduleAddCmd(), a.scheduleListCmd(), a.scheduleShowCmd(),
		a.scheduleRemoveCmd(), a.scheduleEnableCmd(), a.scheduleDisableCmd())
	return cmd
}

func (a *App) scheduleAddCmd() *cobra.Command {
	var name, cronExpr string
	cmd := &cobra.Command{
		Use:     "add --name NAME --cron EXPR -- scan [TARGET...] [flags]",
		Short:   "Store a scan to run on a schedule (fires at most hourly)",
		Example: "  scnr schedule add --name weekly --cron \"0 2 * * 1\" -- scan 10.0.0.0/24 --profile standard",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" || cronExpr == "" {
				return fmt.Errorf("add needs --name and --cron")
			}
			if err := sched.ValidName(name); err != nil {
				return err
			}
			parser, err := sched.ParseCron(cronExpr)
			if err != nil {
				return err
			}
			if _, err := a.parseScheduleArgs(args); err != nil {
				return err
			}
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			now := time.Now()
			err = a.Store.CreateSchedule(cmd.Context(), store.Schedule{
				Name: name, Cron: strings.TrimSpace(cronExpr), Args: args,
				Enabled: true, CreatedBy: audit.Actor(), CreatedAt: now,
				NextRun: parser.Next(now),
			})
			if err != nil {
				return err
			}
			_ = a.Audit.Log(cmd.Context(), audit.ActionSchedule, "", map[string]any{
				"op": "add", "name": name, "cron": strings.TrimSpace(cronExpr), "args": args,
			})
			fmt.Fprintf(a.Stdout, "scheduled %s (%s)\n", name, strings.TrimSpace(cronExpr))
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "schedule name")
	cmd.Flags().StringVar(&cronExpr, "cron", "", "cron expression, at most hourly (5-field or @hourly|@daily|@weekly|@monthly)")
	return cmd
}

func (a *App) scheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored schedules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			rows, err := a.Store.ListSchedules(cmd.Context())
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintln(a.Stdout, "no schedules")
				return nil
			}
			fmt.Fprintf(a.Stdout, "%-20s %-7s %-18s %-20s %s\n", "NAME", "ENABLED", "CRON", "NEXT RUN", "LAST STATUS")
			for _, s := range rows {
				fmt.Fprintf(a.Stdout, "%-20s %-7s %-18s %-20s %s\n",
					s.Name, yesNo(s.Enabled), s.Cron,
					s.NextRun.Format(time.RFC3339), lastStatus(s))
			}
			return nil
		},
	}
}

func (a *App) scheduleShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show one schedule with its full stored arguments",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			s, err := a.Store.GetSchedule(cmd.Context(), args[0])
			if err != nil {
				return scheduleErr(args[0], err)
			}
			lastRun := "-"
			if s.LastRun != nil {
				lastRun = s.LastRun.Format(time.RFC3339)
			}
			fmt.Fprintf(a.Stdout, "name: %s\nenabled: %s\ncron: %s\ncreated_by: %s\ncreated_at: %s\nlast_run: %s\nlast_scan_id: %s\nlast_status: %s\nnext_run: %s\nargs:\n",
				s.Name, yesNo(s.Enabled), s.Cron, s.CreatedBy, s.CreatedAt.Format(time.RFC3339),
				lastRun, orDash(s.LastScanID), orDash(s.LastStatus), s.NextRun.Format(time.RFC3339))
			for _, arg := range s.Args {
				fmt.Fprintf(a.Stdout, "  %s\n", arg)
			}
			return nil
		},
	}
}

func (a *App) scheduleRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove NAME",
		Short: "Delete a schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			if _, err := a.Store.GetSchedule(cmd.Context(), args[0]); err != nil {
				return scheduleErr(args[0], err)
			}
			if err := a.Store.DeleteSchedule(cmd.Context(), args[0]); err != nil {
				return err
			}
			_ = a.Audit.Log(cmd.Context(), audit.ActionSchedule, "", map[string]any{"op": "remove", "name": args[0]})
			fmt.Fprintf(a.Stdout, "removed %s\n", args[0])
			return nil
		},
	}
}

func (a *App) scheduleEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable NAME",
		Short: "Enable a schedule (next run recomputed from now)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.setScheduleEnabled(cmd, args[0], true)
		},
	}
}

func (a *App) scheduleDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable NAME",
		Short: "Disable a schedule (the row is kept)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.setScheduleEnabled(cmd, args[0], false)
		},
	}
}

func (a *App) setScheduleEnabled(cmd *cobra.Command, name string, enabled bool) error {
	if err := a.Open(cmd.Context()); err != nil {
		return err
	}
	s, err := a.Store.GetSchedule(cmd.Context(), name)
	if err != nil {
		return scheduleErr(name, err)
	}
	next := s.NextRun
	op := "disable"
	if enabled {
		op = "enable"
		parser, err := sched.ParseCron(s.Cron)
		if err != nil {
			return err
		}
		next = parser.Next(time.Now())
	}
	if err := a.Store.SetScheduleEnabled(cmd.Context(), name, enabled, next); err != nil {
		return err
	}
	_ = a.Audit.Log(cmd.Context(), audit.ActionSchedule, "", map[string]any{"op": op, "name": name})
	fmt.Fprintf(a.Stdout, "%sd %s\n", op, name)
	return nil
}

func scheduleErr(name string, err error) error {
	if err == store.ErrNotFound {
		return fmt.Errorf("no schedule named %q", name)
	}
	return err
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func lastStatus(s store.Schedule) string {
	return orDash(s.LastStatus)
}

// parseScheduleArgs dry-parses stored argv with the real scan flagset and
// applies the schedule forbidden list. Used at add time and re-run by the
// daemon before every run, so rows injected straight into the database
// are refused the same way (C3).
func (a *App) parseScheduleArgs(argv []string) (wizard.ScanRequest, error) {
	var req wizard.ScanRequest
	if len(argv) == 0 || argv[0] != "scan" {
		return req, fmt.Errorf("schedule argv must start with \"scan\"")
	}
	rest := argv[1:]
	sep := false
	positionals := make([]string, 0, len(rest))
	for _, tok := range rest {
		if !sep && tok == "--" {
			sep = true
			continue
		}
		if !sep && strings.HasPrefix(tok, "--") && tok != "--" {
			name := tok[2:]
			if i := strings.IndexByte(name, '='); i >= 0 {
				name = name[:i]
			}
			if reason, bad := scheduleRefusedReasons[name]; bad {
				return req, fmt.Errorf("schedules refuse --%s: %s", name, reason)
			}
			continue
		}
		positionals = append(positionals, tok)
	}
	// URL-with-credentials targets are refused without running detection
	// (no DNS at add time); the gate refuses them again at run time.
	for _, tok := range positionals {
		if u, err := url.Parse(tok); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.User != nil {
			return req, fmt.Errorf("schedule target %q carries URL credentials", tok)
		}
	}
	var engines, skip string
	fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	scanFlags(fs, &req, &engines, &skip, "")
	if err := fs.Parse(rest); err != nil {
		return req, err
	}
	if pos := fs.Args(); len(pos) == 0 {
		return req, fmt.Errorf("schedules need at least one target")
	} else {
		req.Targets = pos
	}
	req.Engines = splitList(engines)
	req.SkipEngines = splitList(skip)
	req.NonInteractive = true
	return req, nil
}
