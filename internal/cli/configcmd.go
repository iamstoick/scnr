package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/gerald/scnr/internal/config"
	cloudaws "github.com/gerald/scnr/internal/engine/cloud/aws"
	"github.com/gerald/scnr/internal/risk"
)

func (a *App) configCmd() *cobra.Command {
	parent := &cobra.Command{Use: "config", Short: "Show or initialise configuration"}
	var showRisk, awsPolicy bool
	show := &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration (--risk: scoring constants; --aws-policy: minimal IAM policy for cloud scans)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if showRisk {
				fmt.Fprint(a.Stdout, risk.Explain())
				return nil
			}
			if awsPolicy {
				fmt.Fprint(a.Stdout, cloudaws.IAMPolicyJSON())
				return nil
			}
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "home:   %s\ndb:     %s\nconfig: %s\n", a.Home, a.DBPath, orNone(a.ConfigPath))
			if a.configErr != nil {
				fmt.Fprintf(a.Stdout, "config error: %v\n", a.configErr)
				return nil
			}
			b, err := yaml.Marshal(a.Config)
			if err != nil {
				return err
			}
			fmt.Fprintln(a.Stdout, "---")
			a.Stdout.Write(b)
			return nil
		},
	}
	show.Flags().BoolVar(&showRisk, "risk", false, "print the risk/posture scoring constants")
	show.Flags().BoolVar(&awsPolicy, "aws-policy", false, "print the minimal read-only IAM policy the cloud-aws engine needs (SecurityAudit is a superset)")

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create the scnr home directory and an empty scnr.yaml there",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			p := filepath.Join(a.Home, config.FileName)
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(a.Stdout, "%s already exists\n", p)
				return nil
			}
			if err := os.WriteFile(p, []byte(config.Skeleton(config.Authorization{})), 0o600); err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "Wrote %s\n", p)
			return nil
		},
	}
	parent.AddCommand(show, initCmd)
	return parent
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
