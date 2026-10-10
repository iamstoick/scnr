package cli

import (
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/store"
)

// scan list | show live under `scan` as subcommands of a separate parent so
// `scnr scan TARGET` keeps working.
func (a *App) scanListCmds() []*cobra.Command {
	var limit, offset int
	list := &cobra.Command{
		Use:   "list",
		Short: "List past scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			rows, err := a.Store.ListScans(cmd.Context(), limit, offset)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTARTED\tPROFILE\tTARGETS\tFINDINGS\tSCORE\tGRADE")
			for _, r := range rows {
				grade := r.Grade
				if r.Partial {
					grade += " (partial)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%s\n", r.ID, r.StartedAt.Local().Format(time.RFC3339), r.Profile, r.Targets, r.Findings, r.Score, grade)
			}
			return tw.Flush()
		},
	}
	list.Flags().IntVar(&limit, "limit", 50, "rows")
	list.Flags().IntVar(&offset, "offset", 0, "offset")
	show := &cobra.Command{
		Use:   "show SCAN-ID|latest",
		Short: "Show one scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := a.openAndGetScan(ctx, args[0])
			if err != nil {
				return err
			}
			n, _ := a.Store.CountFindings(ctx, sc.ID)
			w := a.Stdout
			fmt.Fprintf(w, "Scan %s\n  started:  %s\n  finished: %s\n  profile:  %s\n  consent:  %s by %s\n  scope:    %s\n  partial:  %v\n  score:    %d (%s)\n  exit:     %d\n  findings: %d\n",
				sc.ID, sc.StartedAt.Format(time.RFC3339), sc.FinishedAt.Format(time.RFC3339), sc.Profile, sc.Consent.Method, sc.Consent.By, sc.ScopeHash, sc.Partial, sc.Posture.Score, sc.Posture.Grade, sc.ExitCode, n)
			fmt.Fprintln(w, "  targets:")
			for _, t := range sc.Targets {
				fmt.Fprintf(w, "    %s (%s, public=%v)\n", t.Value, t.Type, t.Public)
			}
			fmt.Fprintln(w, "  engines:")
			for _, e := range sc.Engines {
				fmt.Fprintf(w, "    %-8s %s %s %s\n", e.Name, e.Status, e.Duration.Round(time.Millisecond), e.Error)
			}
			return nil
		},
	}
	return []*cobra.Command{list, show}
}

func (a *App) findingsCmd() *cobra.Command {
	parent := &cobra.Command{Use: "findings", Short: "Query findings"}
	var fl store.FindingFilter
	var sev string
	var status string
	list := &cobra.Command{
		Use:   "list",
		Short: "List findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			if sev != "" {
				s, ok := domain.ParseSeverity(sev)
				if !ok {
					return exitf(ExitUsage, "bad --severity %q", sev)
				}
				fl.MinSeverity = &s
			}
			fl.Status = domain.Status(status)
			rows, err := a.Store.ListFindings(cmd.Context(), fl)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "RISK\tSEVERITY\tSTATUS\tRULE\tASSET\tLOCATION\tFINGERPRINT")
			for _, f := range rows {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Risk, f.Severity, f.Status, f.RuleID, f.AssetKey, f.Location, f.Fingerprint[:16])
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&fl.ScanID, "scan", "", "scan ID")
	list.Flags().StringVar(&fl.AssetKey, "asset", "", "asset key")
	list.Flags().StringVar(&sev, "severity", "", "minimum severity")
	list.Flags().StringVar(&status, "status", "", "open|fixed|accepted|suppressed")
	list.Flags().IntVar(&fl.Limit, "limit", 50, "rows")
	list.Flags().IntVar(&fl.Offset, "offset", 0, "offset")

	show := &cobra.Command{
		Use:   "show FINGERPRINT",
		Short: "Show one finding with evidence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			fp := args[0]
			if len(fp) < 64 {
				// Prefix lookup via list is not indexed; require the full value
				// but help the user when they pasted a prefix.
				rows, err := a.Store.ListFindings(ctx, store.FindingFilter{Limit: 1000})
				if err != nil {
					return err
				}
				for _, r := range rows {
					if len(r.Fingerprint) >= len(fp) && r.Fingerprint[:len(fp)] == fp {
						fp = r.Fingerprint
						break
					}
				}
			}
			f, err := a.Store.GetFinding(ctx, fp)
			if errors.Is(err, store.ErrNotFound) {
				return exitf(ExitUsage, "finding %q not found", args[0])
			}
			if err != nil {
				return err
			}
			w := a.Stdout
			fmt.Fprintf(w, "%s\n  rule:       %s (%s)\n  asset:      %s\n  location:   %s\n  risk:       %d  severity: %s  confidence: %s  status: %s\n  first seen: %s\n  last seen:  %s\n\nWhat it is:\n  %s\nWhy it matters:\n  %s\nHow to fix:\n  %s\n",
				f.Title, f.RuleID, f.Engine, f.AssetKey, f.Location, f.Risk, f.Severity, f.Confidence, f.Status, f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339), f.WhatItIs, f.WhyItMatters, f.HowToFix)
			if len(f.CVEs) > 0 {
				fmt.Fprintf(w, "CVEs: %v  KEV: %v\n", f.CVEs, f.KEV)
			}
			if len(f.Evidence) > 0 {
				fmt.Fprintln(w, "Evidence (redacted):")
				for _, e := range f.Evidence {
					fmt.Fprintf(w, "  [%s] %s\n    %s\n    sha256=%s\n", e.Kind, e.Location, e.Redacted, e.Hash)
				}
			}
			return nil
		},
	}
	diff := &cobra.Command{
		Use:   "diff SCAN-A SCAN-B",
		Short: "Show findings new in B and fixed since A (B may be 'latest')",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			ids := make([]string, 2)
			for i, arg := range args {
				sc, err := a.openAndGetScan(ctx, arg)
				if err != nil {
					return err
				}
				ids[i] = sc.ID
			}
			return a.printDiff(ctx, ids[0], ids[1])
		},
	}
	parent.AddCommand(list, show, diff)
	return parent
}

func (a *App) assetsCmd() *cobra.Command {
	parent := &cobra.Command{Use: "assets", Short: "Asset inventory"}
	var limit, offset int
	list := &cobra.Command{
		Use:   "list",
		Short: "List assets",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			rows, err := a.Store.ListAssets(cmd.Context(), limit, offset)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tTYPE\tPUBLIC\tFIRST SEEN\tLAST SEEN")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n", r.Key, r.Type, r.Public, r.FirstSeen.Format("2006-01-02"), r.LastSeen.Format("2006-01-02"))
			}
			return tw.Flush()
		},
	}
	list.Flags().IntVar(&limit, "limit", 50, "rows")
	list.Flags().IntVar(&offset, "offset", 0, "offset")
	parent.AddCommand(list)
	return parent
}
