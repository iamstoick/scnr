// Package adapter defines how scnr drives external tools: the Adapter
// interface, Base (exec with argument arrays, minimal env, output caps,
// timeouts) and the forbidden-flag invariant. Concrete adapters live in
// subpackages. Everything here treats tool output as hostile input.
package adapter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
)

// ToolInfo is the result of Detect.
type ToolInfo struct {
	Path    string
	Version string
	OK      bool
	Reason  string
}

// Adapter is an Engine backed by an external binary.
type Adapter interface {
	engine.Engine
	Binary() string
	MinVersion() string
	Detect(ctx context.Context) (ToolInfo, error)
	Args(t domain.Target, o engine.Options) ([]string, error)
	Parse(r io.Reader, emit func(domain.Finding) error) error
}

// Limits for child processes (Section 4).
const (
	MaxStdoutBytes  = 256 << 20
	StderrTailBytes = 8 << 10
	DefaultTimeout  = 15 * time.Minute
)

// allowedEnv is the only environment passed to children.
var allowedEnv = []string{"PATH", "HOME", "TMPDIR"}

var versionRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// Base provides exec plumbing shared by every adapter.
type Base struct {
	BinaryName string
	Min        string
	// VersionArgs defaults to ["--version"].
	VersionArgs []string
	// ExtraEnv lists additional variable names to pass through (prowler).
	ExtraEnv []string
	// SetEnv lists KEY=VALUE pairs always set for the child, after the
	// pass-through variables (so they win): tool knobs that only exist as
	// environment variables, such as grype's DB auto-update switch.
	SetEnv  []string
	path    string
	version string
}

// Detect finds the binary on PATH and parses its version.
func (b *Base) Detect(ctx context.Context) (ToolInfo, error) {
	p, err := exec.LookPath(b.BinaryName)
	if err != nil {
		return ToolInfo{Reason: "not found on PATH"}, nil
	}
	p, err = filepath.Abs(p)
	if err != nil {
		return ToolInfo{Reason: err.Error()}, nil
	}
	args := b.VersionArgs
	if len(args) == 0 {
		args = []string{"--version"}
	}
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(vctx, p, args...)
	cmd.Env = b.env()
	out, _ := cmd.CombinedOutput() // many tools print version to stderr or exit non-zero
	ver := versionRe.FindString(string(out))
	info := ToolInfo{Path: p, Version: ver}
	if ver == "" {
		info.Reason = "could not parse version"
		return info, nil
	}
	if b.Min != "" && CompareVersions(ver, b.Min) < 0 {
		info.Reason = fmt.Sprintf("version %s is older than required %s", ver, b.Min)
		return info, nil
	}
	info.OK = true
	b.path = p
	b.version = ver
	return info, nil
}

func (b *Base) env() []string {
	var env []string
	for _, k := range append(append([]string{}, allowedEnv...), b.ExtraEnv...) {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, b.SetEnv...)
}

// Result of a tool run.
type Result struct {
	StdoutPath string
	StderrTail string
	ExitCode   int
	Duration   time.Duration
}

// Exec runs the detected binary with an argument array (never a shell),
// streaming stdout to a file in scratch (capped) and keeping a stderr tail.
func (b *Base) Exec(ctx context.Context, scratch string, args []string, timeout time.Duration) (*Result, error) {
	if b.path == "" {
		return nil, errors.New("adapter: Detect must succeed before Exec")
	}
	for _, a := range args {
		if strings.ContainsRune(a, 0) {
			return nil, errors.New("adapter: NUL byte in argument")
		}
	}
	if err := CheckForbidden(args); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	outPath := filepath.Join(scratch, b.BinaryName+".stdout")
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer outFile.Close()

	cmd := exec.CommandContext(cctx, b.path, args...)
	cmd.Env = b.env()
	cmd.Dir = scratch
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	tail := &tailBuffer{max: StderrTailBytes}
	cmd.Stderr = tail
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	capped := &cappedWriter{w: bufio.NewWriter(outFile), max: MaxStdoutBytes}
	_, copyErr := io.Copy(capped, stdout)
	if errors.Is(copyErr, errCapExceeded) {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	_ = capped.w.Flush()
	res := &Result{StdoutPath: outPath, StderrTail: tail.String(), Duration: time.Since(start)}
	if errors.Is(copyErr, errCapExceeded) {
		return res, fmt.Errorf("%s produced more than %d bytes; killed", b.BinaryName, MaxStdoutBytes)
	}
	if cctx.Err() != nil {
		return res, fmt.Errorf("%s timed out after %s", b.BinaryName, timeout)
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil // exit codes are mapped by the concrete adapter
	}
	if waitErr != nil {
		return res, waitErr
	}
	return res, nil
}

var errCapExceeded = errors.New("output cap exceeded")

type cappedWriter struct {
	w   *bufio.Writer
	n   int64
	max int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) > c.max {
		return 0, errCapExceeded
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

type tailBuffer struct {
	buf bytes.Buffer
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf.Write(p)
	if t.buf.Len() > t.max {
		b := t.buf.Bytes()
		t.buf = *bytes.NewBuffer(append([]byte(nil), b[len(b)-t.max:]...))
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return t.buf.String() }

// CompareVersions compares dotted numeric versions (-1, 0, 1).
func CompareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Forbidden argument fragments that no adapter may emit (SAFETY.md). The
// invariant test greps arg builders for these and CheckForbidden enforces
// them at exec time.
var Forbidden = []string{
	"--script", "-sU", "-O", "-sC", "-A", // nmap: NSE scripts, UDP, OS detection, default scripts, aggressive
	"-dast", "-fuzz", "brute", "-code", "-headless", "-fr", "-follow-redirects", // nuclei: fuzzing, code/headless protocols, redirect following
	"--autofix", "--dryrun", "--pro", "--metrics=on", "--metrics=auto", "--enable-version-check", // semgrep: never rewrite files, no Pro/cloud engine, no telemetry
	"--server", "--token", "--token-header", "--custom-headers", // trivy: no client/server mode, no credential forwarding
	"--db-auto-update=true", "--only-fixed", // grype: no implicit DB download when offline; never hide unfixed findings
	// prowler: no fixers/remediation, no Security Hub or S3 upload of results, no Slack/Shodan, no browser auth, no user-supplied config file.
	"--fixer", "-S", "--security-hub", "--send-sh-only-fails", "-B", "--output-bucket", "--slack", "--shodan", "--browser-auth", "--config-file",
}

// forbiddenValues are (flag, value) pairs refused regardless of position:
// semgrep's `--config auto` sends project metadata to semgrep.dev.
var forbiddenValues = map[string][]string{"--config": {"auto"}, "-c": {"auto"}, "-f": {"auto"}}

// nmapScanTypeRe matches nmap's combined scan-type switch (`-sTV`, `-sSC`).
// Any combination that switches on UDP (U) or default scripts (C) is refused
// even though the literal `-sU`/`-sC` tokens do not appear.
var nmapScanTypeRe = regexp.MustCompile(`^-s[A-Za-z]+$`)

// CheckForbidden refuses an argv that contains a forbidden flag. Only
// flag-position arguments (leading '-') are inspected: the value of an
// exclusion list such as `-et dos,fuzz,bruteforce` legitimately names the
// behaviours being switched off.
func CheckForbidden(args []string) error {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		flag, value := a, ""
		if j := strings.IndexByte(a, '='); j >= 0 {
			flag, value = a[:j], a[j+1:]
		} else if i+1 < len(args) {
			value = args[i+1]
		}
		for _, f := range Forbidden {
			if strings.HasPrefix(flag, f) || (f == "brute" && strings.Contains(strings.ToLower(flag), f)) || (strings.Contains(f, "=") && a == f) {
				return fmt.Errorf("adapter: forbidden flag %q in argv (SAFETY.md)", a)
			}
		}
		for _, bad := range forbiddenValues[flag] {
			if strings.EqualFold(value, bad) {
				return fmt.Errorf("adapter: forbidden value %q for %s in argv (SAFETY.md)", value, flag)
			}
		}
		if nmapScanTypeRe.MatchString(flag) && strings.ContainsAny(flag[2:], "UC") {
			return fmt.Errorf("adapter: forbidden scan type %q in argv (SAFETY.md)", a)
		}
	}
	return nil
}

// SkipMissing is the SkipError returned when a tool is absent or unusable;
// the scan is marked Partial and doctor explains how to install it.
func SkipMissing(binary string, info ToolInfo) error {
	return &engine.SkipError{Reason: fmt.Sprintf("%s unavailable (%s); run `scnr doctor --install-guide`", binary, info.Reason)}
}

// RunTool is the shared Engine.Run body for adapters: detect the tool
// (absent tools skip rather than fail), build the argv, execute with caps,
// then parse the output file. outputPath names the file the tool was told
// to write; empty means parse captured stdout.
func (b *Base) RunTool(ctx context.Context, ad Adapter, t domain.Target, o engine.Options, emit engine.EmitFunc, outputPath string) error {
	info, err := ad.Detect(ctx)
	if err != nil {
		return err
	}
	if !info.OK {
		return SkipMissing(b.BinaryName, info)
	}
	args, err := ad.Args(t, o)
	if err != nil {
		return err
	}
	if err := CheckForbidden(args); err != nil {
		return err
	}
	if o.Log != nil {
		o.Log.Debug("running adapter", "tool", b.BinaryName, "argv", args)
	}
	if outputPath != "" {
		// Never parse a stale file left by an earlier run in the same scratch.
		if err := os.Remove(outputPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	res, err := b.Exec(ctx, o.Scratch, args, o.Profile.EngineTimeout)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 && outputPath == "" {
		return fmt.Errorf("%s exited %d: %s", b.BinaryName, res.ExitCode, strings.TrimSpace(res.StderrTail))
	}
	path := outputPath
	if path == "" {
		path = res.StdoutPath
	}
	f, err := os.Open(path)
	if err != nil {
		if res.ExitCode != 0 {
			return fmt.Errorf("%s exited %d: %s", b.BinaryName, res.ExitCode, strings.TrimSpace(res.StderrTail))
		}
		return fmt.Errorf("%s produced no output: %w", b.BinaryName, err)
	}
	defer f.Close()
	return ad.Parse(io.LimitReader(f, MaxStdoutBytes), emit)
}

// Version implements engine.Versioned once Detect has run.
func (b *Base) Version() string { return b.version }

// Binary implements Adapter.
func (b *Base) Binary() string { return b.BinaryName }

// MinVersion implements Adapter.
func (b *Base) MinVersion() string { return b.Min }

// PlanTool is the shared Engine.Plan body: an absent or too-old tool yields
// a "will be skipped" plan; otherwise the summary shows the tool version,
// describe and the exact argv the tool will receive.
func (b *Base) PlanTool(ctx context.Context, ad Adapter, t domain.Target, o engine.Options, describe string, est time.Duration) (engine.Plan, error) {
	info, _ := b.Detect(ctx)
	if !info.OK {
		return engine.Plan{Summary: b.BinaryName + " not available (" + info.Reason + "); will be skipped"}, nil
	}
	args, err := ad.Args(t, o)
	var skip *engine.SkipError
	if errors.As(err, &skip) {
		return engine.Plan{Summary: b.BinaryName + " will be skipped for this target: " + skip.Reason}, nil
	}
	if err != nil {
		return engine.Plan{}, err
	}
	return engine.Plan{Summary: b.BinaryName + " " + info.Version + " " + describe + ": " + strings.Join(args, " "), EstDuration: est, Network: true}, nil
}

// FlagSafeValue rejects user-derived values that could be parsed as flags by
// the child process. Targets are validated by the detector first; this is
// defence in depth at the argv boundary.
func FlagSafeValue(v string) error {
	if v == "" || strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t\n\r\x00") {
		return fmt.Errorf("adapter: unsafe argument value %q", v)
	}
	return nil
}

// FlagSafePath is FlagSafeValue for filesystem paths: spaces are legitimate
// in paths (argv entries are never re-split by a shell), but a leading '-'
// or control characters are not, and the path must be absolute so the tool
// cannot interpret it relative to its own working directory.
func FlagSafePath(p string) error {
	if p == "" || strings.HasPrefix(p, "-") || !filepath.IsAbs(p) || strings.ContainsAny(p, "\t\n\r\x00") {
		return fmt.Errorf("adapter: unsafe path argument %q", p)
	}
	return nil
}
