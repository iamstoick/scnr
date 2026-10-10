// Package config loads scnr.yaml (authorization, scope, limits) and resolves
// the scnr home directory.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxConfigBytes caps config file size; the file is user-controlled but we
// still refuse absurd inputs.
const MaxConfigBytes = 1 << 20

// Authorization is the recorded acknowledgment (Section 9).
type Authorization struct {
	Acknowledged bool      `yaml:"acknowledged"`
	By           string    `yaml:"by,omitempty"`
	At           time.Time `yaml:"at,omitempty"`
}

// AckText is the exact statement a user acknowledges.
const AckText = "I am authorised to scan these targets and accept responsibility for doing so."

// Scope lists allow/deny entries. Deny always wins.
type Scope struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// Limits are rate/concurrency caps. Zero means "use the default for the
// target's publicness".
type Limits struct {
	RatePerSec         int `yaml:"rate_per_sec,omitempty"`
	PerHostConcurrency int `yaml:"per_host_concurrency,omitempty"`
	HTTPRPSPerHost     int `yaml:"http_rps_per_host,omitempty"`
	MaxHosts           int `yaml:"max_hosts,omitempty"`
}

// Tools configures external-tool adapters.
type Tools struct {
	// NucleiTemplates is a local nuclei template directory passed to nuclei
	// as -t. Setting it is the opt-in for running nuclei at all against a
	// corpus you control: without it nuclei uses its own default directory,
	// which it populates from GitHub on first run (scnr passes -duc, which
	// only disables the update *check*).
	NucleiTemplates string `yaml:"nuclei_templates,omitempty"`
	// SemgrepRules is a local semgrep rules file or directory passed as
	// --config. Without it the adapter uses the registry pack p/default,
	// which semgrep downloads from semgrep.dev on each run (metrics stay
	// off); set this to run against rules you chose.
	SemgrepRules string `yaml:"semgrep_rules,omitempty"`
}

// Config is the whole scnr.yaml.
type Config struct {
	Authorization Authorization `yaml:"authorization"`
	Scope         Scope         `yaml:"scope"`
	Limits        Limits        `yaml:"limits,omitempty"`
	Tools         Tools         `yaml:"tools,omitempty"`
	Online        *bool         `yaml:"online,omitempty"`
	Path          string        `yaml:"-"`
}

// FileName is the default scope/config file name.
const FileName = "scnr.yaml"

// Home resolves the scnr state directory: SCNR_HOME, else ./.scnr when
// CI=true, else ~/.scnr.
func Home() (string, error) {
	if h := os.Getenv("SCNR_HOME"); h != "" {
		return filepath.Abs(h)
	}
	if os.Getenv("CI") == "true" {
		return filepath.Abs(".scnr")
	}
	uh, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(uh, ".scnr"), nil
}

// EnsureHome creates the home dir (0700) and returns it.
func EnsureHome() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(h, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", h, err)
	}
	return h, nil
}

// Load reads and validates a config file. A missing file yields an empty
// Config and os.ErrNotExist wrapped, so callers can distinguish "absent"
// from "broken".
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return &Config{Path: path}, err
	}
	defer f.Close()
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if n > MaxConfigBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, MaxConfigBytes)
	}
	cfg, err := Parse(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// Parse decodes YAML strictly (unknown fields are errors).
func Parse(b []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks limits are non-negative and tool paths are absolute.
func (c *Config) Validate() error {
	l := c.Limits
	if l.RatePerSec < 0 || l.PerHostConcurrency < 0 || l.HTTPRPSPerHost < 0 || l.MaxHosts < 0 {
		return errors.New("limits must be non-negative")
	}
	if d := c.Tools.NucleiTemplates; d != "" && !filepath.IsAbs(d) {
		return fmt.Errorf("tools.nuclei_templates must be an absolute path, got %q", d)
	}
	if d := c.Tools.SemgrepRules; d != "" && !filepath.IsAbs(d) {
		return fmt.Errorf("tools.semgrep_rules must be an absolute path, got %q", d)
	}
	return nil
}

// Save writes the config with 0600 permissions.
func (c *Config) Save(path string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Skeleton returns a commented starter scnr.yaml.
func Skeleton(ack Authorization) string {
	var b bytes.Buffer
	b.WriteString("# scnr scope and authorization file. See `scnr scope check TARGET`.\n")
	b.WriteString("# The acknowledgment text is: " + AckText + "\n")
	out, _ := yaml.Marshal(Config{
		Authorization: ack,
		Scope:         Scope{Allow: []string{}, Deny: []string{}},
	})
	b.Write(out)
	return b.String()
}
