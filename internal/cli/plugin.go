package cli

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/doctor"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/plugin"
	"github.com/iamstoick/scnr/internal/vulndb"
)

func (a *App) pluginCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "plugin", Short: "Install and manage third-party plugin checks"}
	cmd.AddCommand(a.pluginInstallCmd(), a.pluginListCmd(), a.pluginShowCmd(), a.pluginVerifyCmd(), a.pluginRemoveCmd(), a.pluginSignCmd())
	return cmd
}

func (a *App) pluginInstallCmd() *cobra.Command {
	var allowUnsigned bool
	cmd := &cobra.Command{
		Use:   "install SRC",
		Short: "Install a plugin from a directory or .tar.gz file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			keys, err := a.pluginKeys()
			if err != nil {
				return err
			}
			entry, err := plugin.Install(args[0], plugin.InstallOptions{
				Home:             a.Home,
				RequireSignature: a.pluginRequireSignature(),
				TrustedKeys:      keys,
				AllowUnsigned:    allowUnsigned,
				IsTTY:            a.IsTTY,
				Stdin:            a.Stdin,
				Stdout:           a.Stdout,
				InstalledBy:      audit.Actor(),
				Audit: func(action string, detail map[string]any) {
					_ = a.Audit.Log(cmd.Context(), action, "", detail)
				},
			})
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			fmt.Fprintf(a.Stdout, "installed %s@%s (%s)\n", entry.Name, entry.Version, entry.PublisherKey)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUnsigned, "allow-unsigned", false, "permit the interactive sha256 ceremony for unsigned plugins (TTY only)")
	return cmd
}

func (a *App) pluginListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List installed plugins (newest version per name runs)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			l, err := plugin.LoadLock(a.Home)
			if err != nil {
				return err
			}
			if len(l.Plugins) == 0 {
				fmt.Fprintln(a.Stdout, "no plugins installed")
				return nil
			}
			active := map[string]string{}
			for n, e := range l.Latest() {
				active[n] = e.Version
			}
			for _, e := range l.Plugins {
				mark := " "
				if active[e.Name] == e.Version {
					mark = "*"
				}
				fmt.Fprintf(a.Stdout, "%s %s@%s  network=%s  key=%s\n", mark, e.Name, e.Version, e.Capabilities.Network, e.PublisherKey)
			}
			return nil
		},
	}
}

func (a *App) pluginShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME[@VERSION]",
		Short: "Show an installed plugin's manifest and integrity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			name, version := splitNameVersion(args[0])
			if version == "" {
				version = "latest"
			}
			l, err := plugin.LoadLock(a.Home)
			if err != nil {
				return err
			}
			e, ok := l.Find(name, version)
			if !ok {
				return exitf(ExitUsage, "plugin %s is not installed", args[0])
			}
			raw, err := os.ReadFile(plugin.ManifestPath(a.Home, e))
			if err != nil {
				return err
			}
			m, rules, err := plugin.ParseManifest(raw)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "%s@%s: %s\n  supports: %s  network: %s  rules: %d\n  binary: %.16s…  manifest: %.16s…  key: %s\n",
				m.Name, m.Version, m.Description, strings.Join(m.Supports, ","), m.Capabilities.Network, len(rules),
				e.BinarySHA256, e.ManifestSHA256, e.PublisherKey)
			for _, r := range rules {
				fmt.Fprintf(a.Stdout, "  - %s [%s] %s\n", r.ID, r.Severity, r.Title)
			}
			if err := plugin.Verify(a.Home, e); err != nil {
				fmt.Fprintf(a.Stdout, "  INTEGRITY FAILURE: %v\n", err)
				return exitf(ExitPolicy, "plugin %s@%s failed integrity", e.Name, e.Version)
			}
			fmt.Fprintln(a.Stdout, "  integrity: ok")
			return nil
		},
	}
}

func (a *App) pluginVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Re-hash every installed plugin against the lock file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			l, err := plugin.LoadLock(a.Home)
			if err != nil {
				return err
			}
			var drift []string
			for _, e := range l.Plugins {
				if err := plugin.Verify(a.Home, e); err != nil {
					drift = append(drift, fmt.Sprintf("%s@%s: %v", e.Name, e.Version, err))
					fmt.Fprintf(a.Stdout, "DRIFT %s\n", drift[len(drift)-1])
				}
			}
			_ = a.Audit.Log(cmd.Context(), audit.ActionPluginVerify, "", map[string]any{"plugins": len(l.Plugins), "drift": drift})
			if len(drift) > 0 {
				return exitf(ExitPolicy, "%d plugin(s) drifted from the lock file", len(drift))
			}
			fmt.Fprintf(a.Stdout, "%d plugin(s) verified\n", len(l.Plugins))
			return nil
		},
	}
}

func (a *App) pluginRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove NAME[@VERSION]",
		Short: "Remove installed plugin versions (bare NAME removes all)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			name, version := splitNameVersion(args[0])
			removed, err := plugin.Remove(a.Home, name, version, func(action string, detail map[string]any) {
				_ = a.Audit.Log(cmd.Context(), action, "", detail)
			})
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			for _, e := range removed {
				fmt.Fprintf(a.Stdout, "removed %s@%s\n", e.Name, e.Version)
			}
			return nil
		},
	}
}

func (a *App) pluginSignCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "sign DIR",
		Short: "Set binary_sha256 in DIR/manifest.json and write DIR/manifest.sig (publishers)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return exitf(ExitUsage, "plugin sign needs --key PATH (create one with `scnr db keygen`)")
			}
			seed, err := vulndb.ReadKeyFile(keyPath)
			if err != nil {
				return err
			}
			if err := plugin.SignManifest(args[0], seed); err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			fmt.Fprintln(a.Stdout, "signed", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "signing key file from `scnr db keygen`")
	return cmd
}

func splitNameVersion(s string) (name, version string) {
	name, version, ok := strings.Cut(s, "@")
	if !ok {
		return s, ""
	}
	return name, version
}

// pluginRequireSignature defaults require_signature to true.
func (a *App) pluginRequireSignature() bool {
	if a.Config == nil || a.Config.Plugins.RequireSignature == nil {
		return true
	}
	return *a.Config.Plugins.RequireSignature
}

func (a *App) pluginKeys() ([]ed25519.PublicKey, error) {
	if a.Config == nil {
		return nil, nil
	}
	return vulndb.ParseTrustedKeys(a.Config.Plugins.TrustedKeys)
}

func (a *App) pluginSandboxMode() string {
	if a.Config == nil || a.Config.Plugins.Sandbox == "" {
		return "required"
	}
	return a.Config.Plugins.Sandbox
}

// pluginChecks reports installed-plugin integrity and sandbox state.
func (a *App) pluginChecks() []doctor.Check {
	l, err := plugin.LoadLock(a.Home)
	if err != nil {
		return []doctor.Check{{Name: "plugins", Status: doctor.Fail, Detail: err.Error()}}
	}
	if len(l.Plugins) == 0 {
		return []doctor.Check{{Name: "plugins", Status: doctor.OK, Detail: "none installed"}}
	}
	var out []doctor.Check
	names := []string{}
	latest := l.Latest()
	for n := range latest {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e := latest[n]
		if err := plugin.Verify(a.Home, e); err != nil {
			out = append(out, doctor.Check{Name: "plugin " + n + "@" + e.Version, Status: doctor.Fail, Detail: err.Error()})
			continue
		}
		out = append(out, doctor.Check{Name: "plugin " + n + "@" + e.Version, Status: doctor.OK, Detail: "network=" + e.Capabilities.Network + " key=" + e.PublisherKey})
	}
	sb := plugin.DetectSandbox()
	sandboxName := "none available"
	if sb != nil {
		sandboxName = sb.Name()
	}
	st := doctor.OK
	detail := "wrapper: " + sandboxName + ", mode: " + a.pluginSandboxMode()
	if sb == nil && a.pluginSandboxMode() == "required" {
		st = doctor.Warn
		detail += " (plugins will skip; install bwrap/sandbox-exec or set best-effort)"
	}
	out = append(out, doctor.Check{Name: "plugin sandbox", Status: st, Detail: detail})
	return out
}

// pluginEngines loads installed plugins into engines, collecting
// integrity events for the audit trail.
func (a *App) pluginEngines(events *[]plugin.LoadEvent) ([]engine.Engine, error) {
	return plugin.Load(plugin.LoadOptions{
		Home:        a.Home,
		SandboxMode: a.pluginSandboxMode(),
		Audit: func(action string, detail map[string]any) {
			*events = append(*events, plugin.LoadEvent{Action: action, Detail: detail})
		},
	})
}
