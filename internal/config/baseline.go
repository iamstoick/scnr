package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Baseline is baseline.yaml: findings to report as suppressed. Matching
// findings are shown in their own section, never dropped.
type Baseline struct {
	Version      int       `yaml:"version"`
	CreatedFrom  string    `yaml:"created_from,omitempty"`
	CreatedAt    time.Time `yaml:"created_at,omitempty"`
	Fingerprints []string  `yaml:"fingerprints"`
	Rules        []string  `yaml:"rules,omitempty"`
}

// BaselineVersion is the current file format.
const BaselineVersion = 1

// MaxBaselineEntries bounds the file.
const MaxBaselineEntries = 100000

var fingerprintRe = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ruleIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:@/_-]{2,160}$`)

// LoadBaseline reads and validates a baseline file (strict YAML, capped).
func LoadBaseline(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return nil, err
	}
	bl, err := ParseBaseline(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return bl, nil
}

// ParseBaseline decodes and validates baseline YAML.
func ParseBaseline(b []byte) (*Baseline, error) {
	var bl Baseline
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&bl); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if bl.Version != BaselineVersion {
		return nil, fmt.Errorf("unsupported baseline version %d", bl.Version)
	}
	if len(bl.Fingerprints)+len(bl.Rules) > MaxBaselineEntries {
		return nil, fmt.Errorf("baseline has more than %d entries", MaxBaselineEntries)
	}
	for _, fp := range bl.Fingerprints {
		if !fingerprintRe.MatchString(fp) {
			return nil, fmt.Errorf("bad fingerprint %q", fp)
		}
	}
	for _, r := range bl.Rules {
		if !ruleIDRe.MatchString(r) {
			return nil, fmt.Errorf("bad rule id %q", r)
		}
	}
	return &bl, nil
}

// Marshal renders the baseline as YAML with a comment header.
func (bl *Baseline) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# scnr baseline: findings listed here are reported as suppressed (never dropped).\n")
	buf.WriteString("# Pass with: scnr scan ... --baseline baseline.yaml\n")
	b, err := yaml.Marshal(bl)
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	return buf.Bytes(), nil
}
