package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/audit"
	"github.com/gerald/scnr/internal/store"
)

var fingerprintRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

// parseExpiry accepts Nd (days), Nh (hours) or a Go duration; it must be
// positive and at most store.MaxSuppressionDays.
func parseExpiry(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("--expires is required (e.g. 90d)")
	}
	var d time.Duration
	switch {
	case strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("bad --expires %q", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	default:
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("bad --expires %q (use 90d, 12h, ...)", s)
		}
	}
	if d <= 0 {
		return 0, errors.New("--expires must be positive")
	}
	if d > store.MaxSuppressionDays*24*time.Hour {
		return 0, fmt.Errorf("--expires may not exceed %dd", store.MaxSuppressionDays)
	}
	return d, nil
}

func (a *App) acceptCmd() *cobra.Command {
	var reason, expires, asset string
	cmd := &cobra.Command{
		Use:   "accept FINGERPRINT|RULE-ID",
		Short: "Accept the risk of a finding (by fingerprint) or a rule, with a mandatory reason and expiry",
		Long:  "Accepted findings stay in reports under 'Accepted / suppressed' and do not count towards the score or policy until the acceptance expires (max 365d) or is revoked. Every change is audited.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			if strings.TrimSpace(reason) == "" {
				return exitf(ExitUsage, "--reason is required")
			}
			d, err := parseExpiry(expires)
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			sp := store.Suppression{Reason: reason, CreatedBy: audit.Actor(), CreatedAt: time.Now(), AssetKey: asset}
			sp.ExpiresAt = sp.CreatedAt.Add(d)
			key := args[0]
			if fingerprintRe.MatchString(key) {
				if _, err := a.Store.GetFinding(ctx, key); errors.Is(err, store.ErrNotFound) {
					return exitf(ExitUsage, "finding %s not found", key[:16])
				} else if err != nil {
					return err
				}
				sp.Fingerprint = key
			} else {
				sp.RuleID = key
			}
			sp, applied, err := a.Store.AddSuppression(ctx, sp)
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			_ = a.Audit.Log(ctx, audit.ActionAccept, "", map[string]any{"id": sp.ID, "fingerprint": sp.Fingerprint, "rule_id": sp.RuleID, "asset": sp.AssetKey, "reason": a.redact(sp.Reason), "expires_at": sp.ExpiresAt, "applied": applied})
			fmt.Fprintf(a.Stdout, "Accepted %s until %s (id %s); %d finding(s) marked accepted now.\n", key, sp.ExpiresAt.Format(time.RFC3339), sp.ID[:12], applied)
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why this risk is accepted (required)")
	cmd.Flags().StringVar(&expires, "expires", "", "how long the acceptance lasts, e.g. 90d (required, max 365d)")
	cmd.Flags().StringVar(&asset, "asset", "", "limit a rule acceptance to one asset key")

	var includeRevoked bool
	var limit int
	list := &cobra.Command{
		Use:   "list",
		Short: "List accepted risks",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			rows, err := a.Store.ListSuppressions(ctx, includeRevoked, limit)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tTARGET\tASSET\tEXPIRES\tSTATE\tBY\tREASON")
			now := time.Now()
			for _, sp := range rows {
				target := sp.RuleID
				if sp.Fingerprint != "" {
					target = sp.Fingerprint[:16]
				}
				state := "active"
				switch {
				case !sp.RevokedAt.IsZero():
					state = "revoked"
				case !sp.Active(now):
					state = "expired"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", sp.ID[:12], target, sp.AssetKey, sp.ExpiresAt.Format("2006-01-02"), state, sp.CreatedBy, firstLine(sp.Reason))
			}
			return tw.Flush()
		},
	}
	list.Flags().BoolVar(&includeRevoked, "all", false, "include revoked acceptances")
	list.Flags().IntVar(&limit, "limit", 50, "rows")

	revoke := &cobra.Command{
		Use:   "revoke ID",
		Short: "Revoke an acceptance (findings go back to open)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			sp, reopened, err := a.Store.RevokeSuppression(ctx, args[0])
			if errors.Is(err, store.ErrNotFound) {
				return exitf(ExitUsage, "acceptance %q not found", args[0])
			}
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			_ = a.Audit.Log(ctx, audit.ActionAcceptRevoke, "", map[string]any{"id": sp.ID, "fingerprint": sp.Fingerprint, "rule_id": sp.RuleID, "reopened": reopened})
			fmt.Fprintf(a.Stdout, "Revoked %s; %d finding(s) reopened.\n", sp.ID[:12], reopened)
			return nil
		},
	}
	cmd.AddCommand(list, revoke)
	return cmd
}
