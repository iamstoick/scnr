// Package doctor checks the local environment: config, database, vuln DB
// age, external tools, outbound reachability and disk space.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/config"
	"github.com/gerald/scnr/internal/store"
	"github.com/gerald/scnr/internal/vulndb"
)

// Status values.
const (
	OK      = "OK"
	Missing = "MISSING"
	Old     = "OLD"
	Warn    = "WARN"
	Fail    = "FAIL"
)

// Check is one row of doctor output.
type Check struct {
	Name   string
	Status string
	Detail string
}

// Detector is the part of adapter.Adapter doctor needs (kept as a local
// interface so doctor does not depend on the engine packages).
type Detector interface {
	Detect(ctx context.Context) (adapter.ToolInfo, error)
	MinVersion() string
}

// Options for Run.
type Options struct {
	Home       string
	ConfigPath string
	Store      *store.Store
	Online     bool
	HTTP       *http.Client
	Now        func() time.Time
	// Adapters by binary name; tools with an adapter are version-checked,
	// the rest are only looked up on PATH.
	Adapters map[string]Detector
}

// Run executes all checks. It never returns an error for a failing check;
// it returns an error only if the checks themselves could not run.
func Run(ctx context.Context, o Options) ([]Check, error) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	var out []Check

	// Config.
	var cfg *config.Config
	if o.ConfigPath == "" {
		out = append(out, Check{"config", Warn, "no scnr.yaml; run `scnr scope init`"})
	} else if c, err := config.Load(o.ConfigPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			out = append(out, Check{"config", Warn, o.ConfigPath + " not found; run `scnr scope init`"})
		} else {
			out = append(out, Check{"config", Fail, err.Error()})
		}
	} else {
		cfg = c
		out = append(out, Check{"config", OK, o.ConfigPath})
	}

	// Database.
	if o.Store == nil {
		out = append(out, Check{"database", Fail, "not opened"})
	} else if err := o.Store.Ping(ctx); err != nil {
		out = append(out, Check{"database", Fail, err.Error()})
	} else {
		cur, err := o.Store.SchemaVersion(ctx)
		latest, _ := store.LatestMigrationVersion()
		switch {
		case err != nil:
			out = append(out, Check{"database", Fail, err.Error()})
		case cur < latest:
			out = append(out, Check{"database", Old, fmt.Sprintf("schema %d, latest %d", cur, latest)})
		default:
			out = append(out, Check{"database", OK, fmt.Sprintf("%s (schema %d)", o.Store.Path(), cur)})
		}
		metas, err := o.Store.VulnDBStatus(ctx)
		if err != nil {
			out = append(out, Check{"vulndb", Fail, err.Error()})
		}
		for _, m := range metas {
			name := "vulndb " + m.Source
			switch {
			case m.UpdatedAt.IsZero():
				out = append(out, Check{name, Missing, "not loaded; run `scnr db update`"})
			case now().Sub(m.UpdatedAt) > vulndb.StaleAfter:
				out = append(out, Check{name, Old, fmt.Sprintf("%d rows, updated %s ago; run `scnr db update`", m.Rows, now().Sub(m.UpdatedAt).Round(time.Hour))})
			default:
				out = append(out, Check{name, OK, fmt.Sprintf("%d rows, updated %s ago", m.Rows, now().Sub(m.UpdatedAt).Round(time.Minute))})
			}
		}
	}

	// External tools.
	for _, t := range Tools {
		if d, ok := o.Adapters[t.Tool]; ok {
			info, err := d.Detect(ctx)
			switch {
			case err != nil:
				out = append(out, Check{"tool " + t.Tool, Fail, err.Error()})
			case info.OK:
				out = append(out, Check{"tool " + t.Tool, OK, fmt.Sprintf("%s version %s (adapter enabled)", info.Path, info.Version)})
			case info.Path != "":
				out = append(out, Check{"tool " + t.Tool, Old, fmt.Sprintf("%s: %s (need >= %s); %s", info.Path, info.Reason, d.MinVersion(), installHint(t))})
			default:
				out = append(out, Check{"tool " + t.Tool, Missing, t.Purpose + "; " + installHint(t)})
			}
			continue
		}
		if p, err := exec.LookPath(t.Tool); err == nil {
			out = append(out, Check{"tool " + t.Tool, OK, p + " (adapter arrives in a later phase)"})
		} else {
			out = append(out, Check{"tool " + t.Tool, Missing, t.Purpose + "; " + installHint(t)})
		}
	}
	if _, ok := o.Adapters["nuclei"]; ok {
		out = append(out, nucleiTemplatesCheck(cfg))
	}
	if _, ok := o.Adapters["semgrep"]; ok {
		out = append(out, semgrepRulesCheck(cfg))
	}

	// Raw sockets (informational).
	if os.Geteuid() == 0 {
		out = append(out, Check{"raw sockets", OK, "running as root; nmap SYN scan would be available"})
	} else {
		out = append(out, Check{"raw sockets", Warn, "not root: nmap SYN scan unavailable; TCP connect scan is used (no action needed)"})
	}

	// Outbound (only with --online).
	if o.Online {
		c := o.HTTP
		if c == nil {
			c = &http.Client{Timeout: 10 * time.Second}
		}
		for _, h := range []string{"https://api.osv.dev", "https://www.cisa.gov", "https://epss.cyentia.com"} {
			req, _ := http.NewRequestWithContext(ctx, http.MethodHead, h, nil)
			resp, err := c.Do(req)
			if err != nil {
				out = append(out, Check{"outbound " + h, Fail, err.Error()})
				continue
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			out = append(out, Check{"outbound " + h, OK, fmt.Sprintf("HTTP %d", resp.StatusCode)})
		}
	}

	// Disk space.
	if o.Home != "" {
		if free, err := freeBytes(o.Home); err == nil {
			st := OK
			if free < 200<<20 {
				st = Warn
			}
			out = append(out, Check{"disk " + o.Home, st, fmt.Sprintf("%d MiB free", free>>20)})
		}
	}
	return out, nil
}

// nucleiTemplatesCheck reports whether nuclei will run against a local
// template corpus the operator chose (scnr.yaml tools.nuclei_templates) or
// its own default directory, which nuclei fills from the network on first
// run. scnr passes -duc, which disables only the update check; it cannot
// stop that first-run download, so the operator is told plainly.
func nucleiTemplatesCheck(cfg *config.Config) Check {
	const name = "nuclei templates"
	if cfg == nil || cfg.Tools.NucleiTemplates == "" {
		return Check{name, Warn, "tools.nuclei_templates not set: nuclei uses its default template directory and downloads the corpus from GitHub on first run; set an absolute path to a local corpus to opt in explicitly (SAFETY.md item 10)"}
	}
	dir := cfg.Tools.NucleiTemplates
	st, err := os.Stat(dir)
	switch {
	case err != nil:
		return Check{name, Fail, dir + ": " + err.Error()}
	case !st.IsDir():
		return Check{name, Fail, dir + " is not a directory"}
	}
	return Check{name, OK, dir + " (passed to nuclei as -t)"}
}

// semgrepRulesCheck mirrors nucleiTemplatesCheck: without a local ruleset
// semgrep fetches the registry pack p/default from semgrep.dev on each
// online run (metrics are off; this is the only network it does) and is
// skipped on offline runs.
func semgrepRulesCheck(cfg *config.Config) Check {
	const name = "semgrep rules"
	if cfg == nil || cfg.Tools.SemgrepRules == "" {
		return Check{name, Warn, "tools.semgrep_rules not set: on online scans semgrep fetches the registry pack p/default from semgrep.dev on each run (metrics off); on --offline scans the semgrep engine is skipped. Set an absolute path to a local ruleset to opt in explicitly (SAFETY.md item 10)"}
	}
	p := cfg.Tools.SemgrepRules
	if _, err := os.Stat(p); err != nil {
		return Check{name, Fail, p + ": " + err.Error()}
	}
	return Check{name, OK, p + " (passed to semgrep as --config)"}
}

func installHint(t Guidance) string {
	switch runtime.GOOS {
	case "darwin":
		return t.Brew
	case "linux":
		return t.Apt
	}
	return t.Release
}

func freeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:unconvert // Bsize is int64 on darwin, uint32 on linux
}

// Print writes the table.
func Print(w io.Writer, checks []Check) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tSTATUS\tDETAIL")
	for _, c := range checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, c.Status, c.Detail)
	}
	tw.Flush()
}

// PrintInstallGuide prints copy-pasteable commands for every tool.
func PrintInstallGuide(w io.Writer) {
	fmt.Fprintln(w, "# Install guidance (scnr never runs these for you)")
	for _, t := range Tools {
		fmt.Fprintf(w, "\n## %s — %s\n  macOS:   %s\n  Linux:   %s\n  Release: %s\n", t.Tool, t.Purpose, t.Brew, t.Apt, t.Release)
	}
}

// ListsOutbound is the fixed list of non-target hosts scnr may contact.
func ListsOutbound() []string {
	return []string{"api.osv.dev (SCA lookups, unless --offline)", "www.cisa.gov (KEV, during db update)", "epss.cyentia.com (EPSS, during db update)"}
}

// ToolOutbound lists what the external tools contact on their own when
// their adapters run; scnr cannot route these through its safety dialer,
// so the user is told plainly and --offline suppresses what can be.
func ToolOutbound() []string {
	return []string{
		"semgrep.dev (semgrep rule registry p/default on online scans, unless tools.semgrep_rules is set; metrics off; skipped when --offline)",
		"ghcr.io (trivy vulnerability and check databases, unless --offline; dependency and module resolution over the network is always off via --offline-scan)",
		"grype.anchore.io / toolbox-data.anchore.io (grype vulnerability DB, unless --offline)",
		"github.com (nuclei template corpus on first run, unless tools.nuclei_templates is set)",
	}
}
