package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/doctor"
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
			checks, err := doctor.Run(cmd.Context(), doctor.Options{Home: a.Home, ConfigPath: a.ConfigPath, Store: a.Store, Online: online, Adapters: detectors})
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
