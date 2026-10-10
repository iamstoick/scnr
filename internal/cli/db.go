package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/audit"
	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/store"
	"github.com/gerald/scnr/internal/vulndb"
)

func (a *App) dbCmd() *cobra.Command {
	parent := &cobra.Command{Use: "db", Short: "Manage the local vulnerability data (KEV, EPSS, offline OSV bundles)"}
	var bundlePath string
	var allowUnsigned, allowDowngrade, nonInteractive bool
	update := &cobra.Command{
		Use:   "update",
		Short: "Download the CISA KEV catalogue and FIRST EPSS scores, or load a signed offline OSV bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			if bundlePath != "" {
				return a.loadBundle(ctx, bundlePath, allowUnsigned, allowDowngrade, !nonInteractive && a.IsTTY)
			}
			client, err := a.endpointClient(vulndb.KEVURL, vulndb.EPSSURL, vulndb.EPSSRedirectURL, a.KEVURL, a.EPSSURL)
			if err != nil {
				return err
			}
			u := &vulndb.Updater{Store: a.Store, HTTP: client, KEVURL: a.KEVURL, EPSSURL: a.EPSSURL}
			kev, epss, err := u.UpdateAll(ctx)
			_ = a.Audit.Log(ctx, audit.ActionDBUpdate, "", map[string]any{"kev": kev, "epss": epss, "ok": err == nil})
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "Loaded %d KEV entries and %d EPSS scores.\n", kev, epss)
			return nil
		},
	}
	update.Flags().StringVar(&bundlePath, "offline-bundle", "", "load a signed scnr-osv-*.tar.gz bundle instead of downloading feeds")
	update.Flags().BoolVar(&allowUnsigned, "allow-unsigned", false, "accept a bundle without a signature (interactive sessions only; audited)")
	update.Flags().BoolVar(&allowDowngrade, "allow-downgrade", false, "accept a bundle older than the loaded osv-offline data (interactive sessions only; audited)")
	update.Flags().BoolVar(&nonInteractive, "non-interactive", false, "never prompt; refuse anything needing consent")

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
					hint := "run `scnr db update`"
					if m.Source == store.SourceOSVOffline {
						hint = "load with `scnr db update --offline-bundle PATH`"
					}
					fmt.Fprintf(a.Stdout, "%-11s not loaded (%s)\n", m.Source, hint)
					continue
				}
				fmt.Fprintf(a.Stdout, "%-11s %d rows, updated %s (%s ago) version %q\n", m.Source, m.Rows, m.UpdatedAt.Format(time.RFC3339), time.Since(m.UpdatedAt).Round(time.Minute), m.Version)
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
	parent.AddCommand(update, status, migrate, a.dbKeygenCmd(), a.dbBundleCmd())
	return parent
}

// dbKeygenCmd writes a bundle signing key (0600) and prints the public key
// to put in vulndb.trusted_keys on the machines that will load bundles.
func (a *App) dbKeygenCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Create an ed25519 bundle signing key and print its public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			if out == "" {
				out = filepath.Join(a.Home, vulndb.KeyFileName)
			}
			seed, pub, err := vulndb.GenerateKey()
			if err != nil {
				return err
			}
			if err := vulndb.WriteKeyFile(out, seed); err != nil {
				return exitf(ExitUsage, "%v (an existing key is never overwritten)", err)
			}
			fp := vulndb.KeyFingerprint(pub)
			_ = a.Audit.Log(ctx, audit.ActionKeygen, "", map[string]any{"path": out, "fingerprint": fp})
			fmt.Fprintf(a.Stdout, "Signing key written to %s (mode 0600). Keep it on this machine only.\n", out)
			fmt.Fprintf(a.Stdout, "Public key (add to vulndb.trusted_keys in scnr.yaml on machines that load bundles):\n  %s\nFingerprint: %s\n", vulndb.FormatTrustedKey(pub), fp)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "key file path (default $SCNR_HOME/"+vulndb.KeyFileName+")")
	return cmd
}

func (a *App) dbBundleCmd() *cobra.Command {
	parent := &cobra.Command{Use: "bundle", Short: "Build or verify offline OSV bundles"}
	var out, ecosystems, signKey string
	build := &cobra.Command{
		Use:   "build",
		Short: "Download OSV exports for the given ecosystems and write a bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			ecos := splitList(ecosystems)
			if len(ecos) == 0 {
				return exitf(ExitUsage, "--ecosystems is required (e.g. npm,Go,PyPI)")
			}
			var seed []byte
			if signKey != "" {
				var err error
				if seed, err = vulndb.ReadKeyFile(signKey); err != nil {
					return exitf(ExitUsage, "%v", err)
				}
			} else {
				fmt.Fprintln(a.Stderr, "warning: building an UNSIGNED bundle; it loads only with --allow-unsigned in an interactive session")
			}
			client, err := a.endpointClient(vulndb.DefaultBundleBase, a.BundleBase)
			if err != nil {
				return err
			}
			b := &vulndb.Builder{HTTP: client, Out: out, Ecosystems: ecos, SignSeed: seed, Log: a.Log, Base: a.BundleBase, Builder: "scnr " + a.Version}
			res, err := b.Build(ctx)
			detail := map[string]any{"out": out, "ecosystems": ecos, "signed": seed != nil, "ok": err == nil, "skipped": res.Skipped}
			if err == nil {
				detail["path"] = res.Path
				var n int64
				for _, f := range res.Manifest.Files {
					n += f.Records
				}
				detail["records"] = n
			} else {
				detail["error"] = a.redact(err.Error())
			}
			_ = a.Audit.Log(ctx, audit.ActionBundleBuild, "", detail)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "Bundle written to %s\n", res.Path)
			printManifest(a, res.Manifest)
			if seed != nil {
				fmt.Fprintf(a.Stdout, "Signer: %s\n", vulndb.KeyFingerprint(vulndb.PublicKey(seed)))
			}
			if res.Skipped > 0 {
				fmt.Fprintf(a.Stdout, "Skipped %d malformed or oversized export entries.\n", res.Skipped)
			}
			return nil
		},
	}
	build.Flags().StringVar(&out, "out", ".", "directory to write scnr-osv-<date>.tar.gz into")
	build.Flags().StringVar(&ecosystems, "ecosystems", "", "OSV ecosystems to include (comma list, e.g. npm,Go,PyPI,crates.io)")
	build.Flags().StringVar(&signKey, "sign-key", "", "signing key file from `scnr db keygen`")

	var allowUnsigned bool
	verify := &cobra.Command{
		Use:   "verify PATH",
		Short: "Check a bundle's signature, structure and digests without loading it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := a.Open(ctx); err != nil {
				return err
			}
			rd, err := a.bundleReader()
			if err != nil {
				return err
			}
			res, err := rd.Verify(ctx, args[0], allowUnsigned)
			_ = a.Audit.Log(ctx, audit.ActionBundleVerify, "", bundleDetail(res, args[0], err))
			if err != nil {
				return bundleErr(err)
			}
			fmt.Fprintf(a.Stdout, "Bundle %s verified (sha256 %s)\n", args[0], res.BundleSHA256)
			printManifest(a, res.Manifest)
			if res.Unsigned {
				fmt.Fprintln(a.Stdout, "Signer: none (UNSIGNED bundle)")
			} else {
				fmt.Fprintf(a.Stdout, "Signer: %s\n", res.Signer)
			}
			return nil
		},
	}
	verify.Flags().BoolVar(&allowUnsigned, "allow-unsigned", false, "report an unsigned bundle's contents instead of refusing it")
	parent.AddCommand(build, verify)
	return parent
}

// loadBundle is `db update --offline-bundle`. Unsigned and downgraded
// bundles need both their flag and an interactive session; every outcome
// is audited.
func (a *App) loadBundle(ctx context.Context, path string, allowUnsigned, allowDowngrade, interactive bool) error {
	if !interactive {
		var gate *safety.RefusalError
		switch {
		case allowUnsigned:
			gate = &safety.RefusalError{Code: safety.CodeBundleUntrusted, Target: path, Reason: "--allow-unsigned needs an interactive session (not --non-interactive or a daemon)"}
		case allowDowngrade:
			gate = &safety.RefusalError{Code: safety.CodeBundleDowngrade, Target: path, Reason: "--allow-downgrade needs an interactive session (not --non-interactive or a daemon)"}
		}
		if gate != nil {
			_ = a.Audit.Log(ctx, audit.ActionGateRefused, "", map[string]any{"bundle": path, "error": gate.Error()})
			return &ExitError{Code: ExitRefused, Err: gate}
		}
	}
	rd, err := a.bundleReader()
	if err != nil {
		return err
	}
	rd.Store = a.Store
	res, err := rd.Load(ctx, path, allowUnsigned, allowDowngrade)
	if err != nil {
		if safety.IsRefusal(err) {
			_ = a.Audit.Log(ctx, audit.ActionGateRefused, "", map[string]any{"bundle": path, "error": a.redact(err.Error())})
		} else {
			_ = a.Audit.Log(ctx, audit.ActionDBUpdate, "", bundleDetail(res, path, err))
		}
		return bundleErr(err)
	}
	_ = a.Audit.Log(ctx, audit.ActionDBUpdate, "", bundleDetail(res, path, nil))
	fmt.Fprintf(a.Stdout, "Loaded offline OSV bundle %s: %d affected records", path, res.Records)
	if res.KEV > 0 || res.EPSS > 0 {
		fmt.Fprintf(a.Stdout, ", %d KEV entries, %d EPSS scores", res.KEV, res.EPSS)
	}
	fmt.Fprintln(a.Stdout, ".")
	printManifest(a, res.Manifest)
	if res.Unsigned {
		fmt.Fprintln(a.Stdout, "Signer: none (UNSIGNED bundle accepted with --allow-unsigned)")
	} else {
		fmt.Fprintf(a.Stdout, "Signer: %s\n", res.Signer)
	}
	if res.Downgrade {
		fmt.Fprintln(a.Stdout, "Replaced NEWER osv-offline data with this older bundle (--allow-downgrade).")
	}
	return nil
}

// bundleReader builds a reader with the configured trusted keys.
func (a *App) bundleReader() (*vulndb.BundleReader, error) {
	if a.configErr != nil {
		return nil, fmt.Errorf("scope file: %w", a.configErr)
	}
	keys, err := vulndb.ParseTrustedKeys(a.Config.VulnDB.TrustedKeys)
	if err != nil {
		return nil, exitf(ExitUsage, "scnr.yaml vulndb.trusted_keys: %v", err)
	}
	return &vulndb.BundleReader{Keys: keys, Redactor: a.Redactor}, nil
}

// bundleErr maps a refusal to exit 3 and leaves other errors as usage errors.
func bundleErr(err error) error {
	if safety.IsRefusal(err) {
		return &ExitError{Code: ExitRefused, Err: err}
	}
	return err
}

func bundleDetail(res vulndb.LoadResult, path string, err error) map[string]any {
	d := map[string]any{"bundle": res.BundleSHA256, "path": path, "signer": res.Signer, "unsigned": res.Unsigned, "downgrade": res.Downgrade,
		"ecosystems": res.Manifest.Ecosystems, "records": res.Records, "kev": res.KEV, "epss": res.EPSS, "ok": err == nil}
	if err != nil {
		d["error"] = err.Error()
	}
	return d
}

func printManifest(a *App, m vulndb.Manifest) {
	fmt.Fprintf(a.Stdout, "Created %s by %s from %s; ecosystems: %s\n", m.CreatedAt.Format(time.RFC3339), m.Builder, m.Source, strings.Join(m.Ecosystems, ", "))
	for _, f := range m.Files {
		fmt.Fprintf(a.Stdout, "  %-32s %10d records %12d bytes\n", f.Name, f.Records, f.Bytes)
	}
	if m.KEV != nil {
		fmt.Fprintf(a.Stdout, "  %-32s %10d entries\n", m.KEV.Name, m.KEV.Records)
	}
	if m.EPSS != nil {
		fmt.Fprintf(a.Stdout, "  %-32s %10d entries\n", m.EPSS.Name, m.EPSS.Records)
	}
}

// endpointClient returns a client allowed to reach only the hosts named by
// urls (empty strings are skipped; tests substitute httptest URLs).
func (a *App) endpointClient(urls ...string) (*http.Client, error) {
	var hosts []string
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("endpoint %q: not a URL", raw)
		}
		hosts = append(hosts, u.Hostname())
	}
	if len(hosts) == 0 {
		return nil, errors.New("endpoint client: no hosts")
	}
	return safety.NewEndpointClient(hosts, safety.HTTPOptions{Timeout: 5 * time.Minute, UserAgent: "scnr/" + a.Version})
}
