package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/config"
)

func (a *App) baselineCmd() *cobra.Command {
	parent := &cobra.Command{Use: "baseline", Short: "Create a baseline of known findings to report as suppressed"}
	var from string
	create := &cobra.Command{
		Use:   "create --from SCAN-ID",
		Short: "Write a baseline.yaml (to stdout) listing every finding of a scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if from == "" {
				return exitf(ExitUsage, "--from SCAN-ID is required")
			}
			sc, err := a.openAndGetScan(ctx, from)
			if err != nil {
				return err
			}
			fps, rules, err := a.Store.ScanFingerprintsAndRules(ctx, sc.ID)
			if err != nil {
				return err
			}
			if fps == nil {
				fps = []string{}
			}
			bl := &config.Baseline{Version: config.BaselineVersion, CreatedFrom: sc.ID, CreatedAt: time.Now().UTC().Truncate(time.Second), Fingerprints: fps, Rules: rules}
			b, err := bl.Marshal()
			if err != nil {
				return err
			}
			_, err = a.Stdout.Write(b)
			return err
		},
	}
	create.Flags().StringVar(&from, "from", "", "scan ID (or latest) whose findings form the baseline")
	parent.AddCommand(create)
	return parent
}
