package cli

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/audit"
	"github.com/gerald/scnr/internal/store"
	"github.com/gerald/scnr/internal/vulndb"
)

func (a *App) dbCmd() *cobra.Command {
	parent := &cobra.Command{Use: "db", Short: "Manage the local vulnerability data (KEV, EPSS)"}
	update := &cobra.Command{
		Use:   "update",
		Short: "Download the CISA KEV catalogue and FIRST EPSS scores",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			u := &vulndb.Updater{Store: a.Store, HTTP: &http.Client{Timeout: 5 * time.Minute}, KEVURL: a.KEVURL, EPSSURL: a.EPSSURL}
			kev, epss, err := u.UpdateAll(ctx)
			_ = a.Audit.Log(ctx, audit.ActionDBUpdate, "", map[string]any{"kev": kev, "epss": epss, "ok": err == nil})
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "Loaded %d KEV entries and %d EPSS scores.\n", kev, epss)
			return nil
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show vulnerability data freshness",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			metas, err := a.Store.VulnDBStatus(ctx)
			if err != nil {
				return err
			}
			for _, m := range metas {
				if m.UpdatedAt.IsZero() {
					fmt.Fprintf(a.Stdout, "%-5s not loaded (run `scnr db update`)\n", m.Source)
					continue
				}
				fmt.Fprintf(a.Stdout, "%-5s %d rows, updated %s (%s ago) version %q\n", m.Source, m.Rows, m.UpdatedAt.Format(time.RFC3339), time.Since(m.UpdatedAt).Round(time.Minute), m.Version)
			}
			return nil
		},
	}
	var down int
	var ackAuditLoss bool
	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending schema migrations (or roll back with --down N)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			if down > 0 {
				n, err := a.Store.AuditRowCount(ctx)
				if err != nil {
					return err
				}
				if n > 0 && !ackAuditLoss {
					return exitf(ExitRefused, "%v: %d rows; pass --i-understand-audit-loss to roll back anyway", store.ErrAuditLoss, n)
				}
				if n > 0 {
					// Recorded before the rollback so the decision itself is audited.
					if err := a.Audit.Log(ctx, audit.ActionMigrateDown, "", map[string]any{"down": down, "audit_rows": n, "acknowledged": true}); err != nil {
						return err
					}
				}
				if err := a.Store.MigrateDown(ctx, down, ackAuditLoss); err != nil {
					return err
				}
			} else if err := a.Store.Migrate(ctx); err != nil {
				return err
			}
			v, err := a.Store.SchemaVersion(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "schema version %d\n", v)
			return nil
		},
	}
	migrate.Flags().IntVar(&down, "down", 0, "roll back N migrations")
	migrate.Flags().BoolVar(&ackAuditLoss, "i-understand-audit-loss", false, "allow --down when audit_log has rows (the rollback is audited first)")
	parent.AddCommand(update, status, migrate)
	return parent
}
