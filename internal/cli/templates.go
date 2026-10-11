package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/engine/webscan"
)

func (a *App) templatesCmd() *cobra.Command {
	parent := &cobra.Command{Use: "templates", Short: "List or validate webscan templates"}
	var dir string
	list := &cobra.Command{
		Use:   "list",
		Short: "List embedded templates (plus --templates DIR)",
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := webscan.New()
			if err != nil {
				return err
			}
			tpls, err := e.Templates(dir)
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			tw := tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tSAFETY\tREQUESTS\tTITLE")
			for _, t := range tpls {
				n := 0
				for _, s := range t.HTTP {
					n += len(s.Path)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", t.ID, t.Info.Severity, t.Safety, n, t.Info.Title)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "%d template(s) (%d embedded)\n", len(tpls), e.EmbeddedCount())
			return nil
		},
	}
	list.Flags().StringVar(&dir, "templates", "", "extra template directory")

	validate := &cobra.Command{
		Use:   "validate PATH",
		Short: "Lint a template file or directory; exit 1 on any error",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := os.Stat(args[0])
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			var tpls []*webscan.Template
			var errs []error
			if st.IsDir() {
				tpls, errs = webscan.LoadDir(args[0])
			} else {
				b, err := os.ReadFile(args[0])
				if err != nil {
					return exitf(ExitUsage, "%v", err)
				}
				t, perr := webscan.ParseTemplate(b, filepath.Base(args[0]))
				if perr != nil {
					errs = append(errs, perr)
				} else {
					tpls = append(tpls, t)
				}
			}
			for _, t := range tpls {
				note := ""
				if t.Safety != "safe" {
					note = "  (intrusive: will not run in this version)"
				}
				fmt.Fprintf(a.Stdout, "OK    %s  %s%s\n", t.Source, t.ID, note)
			}
			for _, e := range errs {
				fmt.Fprintf(a.Stdout, "ERROR %v\n", e)
			}
			if len(errs) > 0 {
				return &ExitError{Code: ExitPolicy}
			}
			return nil
		},
	}
	parent.AddCommand(list, validate)
	return parent
}
