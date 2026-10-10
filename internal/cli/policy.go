package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/audit"
	"github.com/gerald/scnr/internal/config"
)

func (a *App) policyCmd() *cobra.Command {
	parent := &cobra.Command{Use: "policy", Short: "Evaluate policy-as-code against a scan"}
	var path string
	check := &cobra.Command{
		Use:   "check SCAN-ID|latest --policy policy.yaml",
		Short: "Exit 1 if the scan violates the policy, 0 if it passes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if path == "" {
				return exitf(ExitUsage, "--policy is required")
			}
			policy, err := config.LoadPolicy(path)
			if err != nil {
				return exitf(ExitUsage, "--policy: %v", err)
			}
			sc, err := a.openAndGetScan(ctx, args[0])
			if err != nil {
				return err
			}
			counts, err := a.scanCounts(ctx, sc.ID)
			if err != nil {
				return err
			}
			violations := policy.Evaluate(policyInput(counts, sc))
			_ = a.Audit.Log(ctx, audit.ActionPolicyCheck, sc.ID, map[string]any{"path": path, "violations": violations})
			for _, v := range violations {
				fmt.Fprintln(a.Stdout, "POLICY FAIL:", v)
			}
			if len(violations) > 0 {
				return &ExitError{Code: ExitPolicy}
			}
			fmt.Fprintf(a.Stdout, "POLICY PASS: %s (scan %s, score %d)\n", path, sc.ID, sc.Posture.Score)
			return nil
		},
	}
	check.Flags().StringVar(&path, "policy", "", "policy.yaml")
	parent.AddCommand(check)
	return parent
}
