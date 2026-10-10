package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func (a *App) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the scnr version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(a.Stdout, "scnr %s (%s, %s/%s)\n", a.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}
