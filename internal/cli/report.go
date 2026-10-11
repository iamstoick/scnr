package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/report"
	"github.com/iamstoick/scnr/internal/vulndb"
)

func (a *App) reportCmd() *cobra.Command {
	var formats, out string
	cmd := &cobra.Command{
		Use:   "report SCAN-ID|latest",
		Short: "Re-render reports for a past scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			scan, err := a.openAndGetScan(ctx, args[0])
			if err != nil {
				return err
			}
			enr, err := vulndb.NewEnricher(ctx, a.Store)
			if err != nil {
				return err
			}
			meta := report.Meta{ExploitData: enr.Available, Version: a.Version}
			if prev, ok, _ := a.Store.PreviousScanScore(ctx, scan.TargetSetHash, scan.ID); ok {
				meta.PreviousScore = &prev
			}
			reporters, err := report.ParseFormats(formats, report.Registry(meta))
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			paths, err := report.WriteAll(ctx, a.Store, *scan, reporters, filepath.Join(out, scan.ID))
			if err != nil {
				return err
			}
			for _, p := range paths {
				fmt.Fprintln(a.Stdout, p)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&formats, "format", "html,json", "report formats (comma list)")
	cmd.Flags().StringVar(&out, "out", "./scnr-out", "output directory")
	return cmd
}
