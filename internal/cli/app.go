// Package cli defines the cobra command tree. One file per command.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/spf13/cobra"

	"github.com/iamstoick/scnr/internal/audit"
	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/logx"
	"github.com/iamstoick/scnr/internal/safety"
	"github.com/iamstoick/scnr/internal/store"
)

// Exit codes (Section 5.8).
const (
	ExitOK        = 0
	ExitPolicy    = 1
	ExitUsage     = 2
	ExitRefused   = 3
	ExitAllFailed = 4
	ExitPartial   = 5
)

// ExitError carries a process exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

func exitf(code int, format string, args ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}

// App holds process-wide dependencies. Tests construct it directly.
type App struct {
	Version    string
	Home       string
	DBPath     string
	ConfigPath string
	AuditFile  string
	Store      *store.Store
	Audit      *audit.Writer
	Config     *config.Config
	Log        *slog.Logger
	Redactor   *safety.Redactor
	Stdout     io.Writer
	Stderr     io.Writer
	Stdin      io.Reader
	IsTTY      bool
	Resolver   safety.Resolver
	// Test hooks for upstream services.
	OSVBase    string
	KEVURL     string
	EPSSURL    string
	BundleBase string
	// AWSEndpoint points every AWS service client at a fake (tests only);
	// no flag sets it (TestCLIDoesNotExposeEndpointOverride).
	AWSEndpoint string
	Verbose     bool

	configErr  error      // set when scnr.yaml exists but is invalid
	progressMu sync.Mutex // serialises engine progress lines from concurrent engines
}

// NewApp returns an App with stdio defaults; Open must be called before
// commands that need the store.
func NewApp(version string) *App {
	return &App{Version: version, Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, Redactor: safety.NewRedactor()}
}

// Open resolves home, opens the store and audit writer, loads config.
func (a *App) Open(ctx context.Context) error {
	if a.Store != nil {
		return nil
	}
	if a.Home == "" {
		h, err := config.EnsureHome()
		if err != nil {
			return err
		}
		a.Home = h
	} else if err := os.MkdirAll(a.Home, 0o700); err != nil {
		return err
	}
	if a.DBPath == "" {
		a.DBPath = filepath.Join(a.Home, "scnr.db")
	}
	if a.Log == nil {
		lvl := slog.LevelInfo
		if a.Verbose {
			lvl = slog.LevelDebug
		}
		// The logger and engine progress lines share stderr from concurrent
		// goroutines; serialise them on the same mutex.
		a.Log = logx.New(logx.Options{Level: lvl, Out: &lockedWriter{mu: &a.progressMu, w: a.Stderr}, IsTTY: a.IsTTY, Redactor: a.Redactor})
	}
	s, err := store.Open(a.DBPath)
	if err != nil {
		return fmt.Errorf("open database %s: %w", a.DBPath, err)
	}
	a.Store = s
	aw, err := audit.New(s, a.AuditFile)
	if err != nil {
		s.Close() //nolint:errcheck // best effort; the audit error is the real one
		return err
	}
	a.Audit = aw
	if a.Config == nil {
		a.loadConfig()
	}
	return nil
}

// loadConfig looks for scnr.yaml at --scope, ./scnr.yaml, then <home>/scnr.yaml.
// A missing file yields an empty config; a broken file is an error the user
// sees once (we do not silently ignore a bad scope file).
func (a *App) loadConfig() {
	candidates := []string{}
	if a.ConfigPath != "" {
		candidates = append(candidates, a.ConfigPath)
	} else {
		candidates = append(candidates, config.FileName, filepath.Join(a.Home, config.FileName))
	}
	for _, p := range candidates {
		cfg, err := config.Load(p)
		if err == nil {
			a.Config = cfg
			a.ConfigPath = p
			return
		}
		if !errors.Is(err, os.ErrNotExist) {
			a.Config = &config.Config{Path: p}
			a.configErr = err
			a.ConfigPath = p
			return
		}
	}
	a.Config = &config.Config{}
	if a.ConfigPath == "" {
		a.ConfigPath = ""
	}
}

// openAndGetScan opens the store and loads a scan by ID or "latest",
// mapping not-found to a usage error.
func (a *App) openAndGetScan(ctx context.Context, id string) (*domain.Scan, error) {
	if err := a.Open(ctx); err != nil {
		return nil, err
	}
	sc, err := a.Store.GetScan(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, exitf(ExitUsage, "scan %q not found", id)
	}
	return sc, err
}

// Close releases resources.
func (a *App) Close() {
	if a.Audit != nil {
		a.Audit.Close() //nolint:errcheck // shutdown path; nothing actionable
	}
	if a.Store != nil {
		a.Store.Close() //nolint:errcheck // shutdown path; nothing actionable
		a.Store = nil
	}
}

// Root builds the command tree.
func (a *App) Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "scnr",
		Short:         "Defensive vulnerability discovery for your own systems",
		Long:          "scnr points at a URL, host, network range or code directory you own and reports vulnerabilities in plain English. It observes; it never exploits.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runWizard(cmd.Context())
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&a.DBPath, "db", "", "SQLite database path (default $SCNR_HOME/scnr.db)")
	pf.StringVar(&a.ConfigPath, "scope", "", "scope/authorization file (default ./scnr.yaml or $SCNR_HOME/scnr.yaml)")
	pf.StringVar(&a.AuditFile, "audit-file", "", "mirror audit rows to this JSONL file")
	pf.BoolVarP(&a.Verbose, "verbose", "v", false, "debug logging")

	root.AddCommand(a.scanCmd(), a.doctorCmd(), a.reportCmd(), a.findingsCmd(), a.assetsCmd(), a.scopeCmd(), a.verifyCmd(), a.dbCmd(), a.configCmd(), a.versionCmd(),
		a.acceptCmd(), a.baselineCmd(), a.policyCmd(), a.templatesCmd(), a.sbomCmd(),
		a.scheduleCmd(), a.daemonCmd())
	return root
}

// Execute runs args and returns the process exit code.
func Execute(ctx context.Context, a *App, args []string) int {
	root := a.Root()
	root.SetArgs(args)
	root.SetOut(a.Stdout)
	root.SetErr(a.Stderr)
	root.SetIn(ioReader(a.Stdin))
	err := root.ExecuteContext(ctx)
	a.Close()
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			fmt.Fprintln(a.Stderr, "error:", a.redact(ee.Err.Error()))
		}
		return ee.Code
	}
	fmt.Fprintln(a.Stderr, "error:", a.redact(err.Error()))
	return ExitUsage
}

// lockedWriter serialises writes to a shared stream.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func ioReader(r io.Reader) io.Reader {
	if r == nil {
		return os.Stdin
	}
	return r
}
