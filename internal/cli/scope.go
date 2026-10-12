package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/safety"
)

func (a *App) scopeCmd() *cobra.Command {
	parent := &cobra.Command{Use: "scope", Short: "Manage the scope/authorization file"}
	var out string
	var yes bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a scnr.yaml skeleton after recording your authorization acknowledgment",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			if _, err := os.Stat(out); err == nil {
				return exitf(ExitUsage, "%s already exists; edit it instead", out)
			}
			ack := config.Authorization{}
			if yes || a.confirmAck() {
				ack = config.Authorization{Acknowledged: true, By: audit.Actor(), At: time.Now().UTC().Truncate(time.Second)}
			} else {
				fmt.Fprintln(a.Stdout, "Acknowledgment not given; writing scnr.yaml with acknowledged: false.")
			}
			if err := os.WriteFile(out, []byte(config.Skeleton(ack)), 0o600); err != nil {
				return err
			}
			_ = a.Audit.Log(ctx, audit.ActionScopeInit, "", map[string]any{"path": out, "acknowledged": ack.Acknowledged})
			abs, _ := filepath.Abs(out)
			fmt.Fprintf(a.Stdout, "Wrote %s. Add your systems under scope.allow before scanning public targets.\n", abs)
			return nil
		},
	}
	initCmd.Flags().StringVar(&out, "out", config.FileName, "where to write the file")
	initCmd.Flags().BoolVar(&yes, "yes", false, "record the acknowledgment without prompting (only when you are authorised)")

	check := &cobra.Command{
		Use:   "check TARGET",
		Short: "Explain what the safety gate would decide for a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			if a.configErr != nil {
				return exitf(ExitUsage, "scope file: %v", a.configErr)
			}
			t, err := a.Detector().Detect(ctx, args[0], "")
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			scope, err := safety.NewScope(a.Config.Scope.Allow, a.Config.Scope.Deny, a.Config.Scope.IntrusiveAllow)
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			verifier := &safety.Verifier{Store: a.Store}
			gate := &safety.Gate{Scope: scope, Acknowledged: a.Config.Authorization.Acknowledged, Resolver: a.Resolver, Verified: verifier.IsVerified}
			w := a.Stdout
			fmt.Fprintf(w, "target:   %s (%s) public=%v\n", t.Value, t.Type, t.Public)
			fmt.Fprintf(w, "scope:    %s (hash %s)\n", a.ConfigPath, scope.Hash()[:12])
			fmt.Fprintf(w, "ack:      %v (scnr.yaml); --ack-authorized would also satisfy it\n", a.Config.Authorization.Acknowledged)
			dec, err := gate.Decide(ctx, t, "")
			if err != nil {
				fmt.Fprintf(w, "decision: REFUSE non-interactively — %v\n", err)
				if t.Public && gate.Acknowledged {
					fmt.Fprintln(w, "          an interactive scan (TTY, no --non-interactive) would ask for consent instead")
				}
				return nil
			}
			fmt.Fprintf(w, "decision: ALLOW (consent method %s, %d host(s))\n", dec.ConsentMethod, dec.HostCount)
			if t.Type == domain.TargetURL {
				ig := &safety.IntrusiveGate{Scope: scope, Verified: verifier.IsVerified}
				ok, reason, err := ig.Decide(ctx, dec, true)
				switch {
				case err != nil:
					fmt.Fprintf(w, "intrusive: ERROR %v\n", err)
				case ok:
					fmt.Fprintln(w, "intrusive: ALLOW with --allow-intrusive")
				default:
					fmt.Fprintf(w, "intrusive: SKIP with --allow-intrusive — %s\n", reason)
				}
			}
			return nil
		},
	}
	parent.AddCommand(initCmd, check)
	return parent
}

func (a *App) confirmAck() bool {
	if !a.IsTTY {
		return false
	}
	fmt.Fprintf(a.Stdout, "%s\nType \"yes\" to acknowledge: ", config.AckText)
	line, _ := bufio.NewReader(a.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "yes")
}
