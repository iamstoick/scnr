package cli

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/safety"
)

func (a *App) verifyCmd() *cobra.Command {
	var printToken, check bool
	cmd := &cobra.Command{
		Use:   "verify DOMAIN|IP",
		Short: "Prove you own a public host so it can be scanned non-interactively",
		Long: "Prints a token to publish as a DNS TXT record at _scnr-verify.DOMAIN or at https://DOMAIN/.well-known/scnr-verify.txt, " +
			"then --check confirms it and records a 30-day verification. A TXT record on a domain also covers its subdomains.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			host := args[0]
			secret, err := safety.LoadOrCreateSecret(a.Home)
			if err != nil {
				return err
			}
			token := safety.Token(secret, host)
			if printToken || !check {
				fmt.Fprintf(a.Stdout, "%s%s\n", safety.VerifyRecordPrefix, token)
				if !check {
					fmt.Fprintf(a.Stderr, "Publish as TXT at %s%s or at https://%s%s then run: scnr verify %s --check\n", safety.VerifyTXTPrefix, host, host, safety.VerifyWellKnownPath, host)
					return nil
				}
			}
			scope, err := safety.NewScope(append(a.Config.Scope.Allow, host), a.Config.Scope.Deny)
			if err != nil {
				return err
			}
			limits, _, _ := safety.NewLimits(true, safety.LimitRequest{})
			dialer := &safety.Dialer{Scope: scope, Resolver: a.Resolver, Limits: limits}
			v := &safety.Verifier{Store: a.Store, Secret: secret, TXT: a.txtResolver(), HTTP: safety.NewHTTPClient(dialer, safety.HTTPOptions{})}
			method, err := v.Check(ctx, host)
			_ = a.Audit.Log(ctx, audit.ActionVerify, "", map[string]any{"host": host, "method": method, "ok": err == nil})
			if err != nil {
				return exitf(ExitRefused, "%v", err)
			}
			fmt.Fprintf(a.Stdout, "Verified %s via %s; valid for 30 days.\n", host, method)
			return nil
		},
	}
	cmd.Flags().BoolVar(&printToken, "print-token", false, "print the token to publish")
	cmd.Flags().BoolVar(&check, "check", false, "look for the published token and record the verification")
	return cmd
}

// txtResolver returns the TXT resolver: the injected resolver when it also
// supports TXT (tests), else the system resolver.
func (a *App) txtResolver() safety.TXTResolver {
	if r, ok := a.Resolver.(safety.TXTResolver); ok {
		return r
	}
	return net.DefaultResolver
}
