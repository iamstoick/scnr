package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/gerald/scnr/internal/domain"
)

// Policy is policy.yaml (Section 5.8): CI gating rules evaluated over the
// open findings of a scan. Buckets refer to the Risk bucket (Section 7).
type Policy struct {
	FailOn          string         `yaml:"fail_on,omitempty"`          // bucket name: any open finding at or above fails
	FailOnKEV       bool           `yaml:"fail_on_kev,omitempty"`      // any open KEV finding fails
	MaxFindings     map[string]int `yaml:"max_findings,omitempty"`     // per bucket caps
	MinScore        *int           `yaml:"min_score,omitempty"`        // posture score floor
	RequiredEngines []string       `yaml:"required_engines,omitempty"` // engines that must have run ok
	FailOnPartial   bool           `yaml:"fail_on_partial,omitempty"`  // any engine skipped/failed/timed out fails
	Path            string         `yaml:"-"`
}

var bucketRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// LoadPolicy reads and validates a policy file (strict YAML, size capped).
func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxConfigBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, MaxConfigBytes)
	}
	p, err := ParsePolicy(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Path = path
	return p, nil
}

// ParsePolicy decodes and validates policy YAML.
func ParsePolicy(b []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks bucket names and ranges.
func (p *Policy) Validate() error {
	if p.FailOn != "" {
		if _, ok := bucketRank[strings.ToLower(p.FailOn)]; !ok {
			return fmt.Errorf("fail_on: unknown bucket %q (info|low|medium|high|critical)", p.FailOn)
		}
	}
	for b, n := range p.MaxFindings {
		if _, ok := bucketRank[strings.ToLower(b)]; !ok {
			return fmt.Errorf("max_findings: unknown bucket %q", b)
		}
		if n < 0 {
			return fmt.Errorf("max_findings.%s must be >= 0", b)
		}
	}
	if p.MinScore != nil && (*p.MinScore < 0 || *p.MinScore > 100) {
		return errors.New("min_score must be 0..100")
	}
	if p.FailOn == "" && !p.FailOnKEV && len(p.MaxFindings) == 0 && p.MinScore == nil && len(p.RequiredEngines) == 0 && !p.FailOnPartial {
		return errors.New("policy has no rules")
	}
	return nil
}

// PolicyInput is what Evaluate needs; counts cover open findings only.
type PolicyInput struct {
	OpenByBucket map[string]int
	KEVOpen      bool
	Score        int
	Partial      bool
	Engines      []domain.EngineRun
}

// Evaluate returns one line per violated rule; empty means pass.
func (p *Policy) Evaluate(in PolicyInput) []string {
	var v []string
	if p.FailOn != "" {
		min := bucketRank[strings.ToLower(p.FailOn)]
		n := 0
		for b, c := range in.OpenByBucket {
			if bucketRank[b] >= min {
				n += c
			}
		}
		if n > 0 {
			v = append(v, fmt.Sprintf("fail_on %s: %d open finding(s) at or above %s", p.FailOn, n, p.FailOn))
		}
	}
	if p.FailOnKEV && in.KEVOpen {
		v = append(v, "fail_on_kev: an open finding is on the CISA KEV list")
	}
	buckets := make([]string, 0, len(p.MaxFindings))
	for b := range p.MaxFindings {
		buckets = append(buckets, b)
	}
	sort.Strings(buckets)
	for _, b := range buckets {
		if n := in.OpenByBucket[strings.ToLower(b)]; n > p.MaxFindings[b] {
			v = append(v, fmt.Sprintf("max_findings.%s: %d open > %d allowed", b, n, p.MaxFindings[b]))
		}
	}
	if p.MinScore != nil && in.Score < *p.MinScore {
		v = append(v, fmt.Sprintf("min_score: posture %d < %d", in.Score, *p.MinScore))
	}
	ran := map[string]string{}
	for _, e := range in.Engines {
		ran[e.Name] = e.Status
	}
	for _, name := range p.RequiredEngines {
		if st, ok := ran[name]; !ok || st != "ok" {
			if !ok {
				st = "did not run"
			}
			v = append(v, fmt.Sprintf("required_engines: %s %s", name, st))
		}
	}
	if p.FailOnPartial && in.Partial {
		var incomplete []string
		for _, e := range in.Engines {
			if e.Status != "ok" {
				incomplete = append(incomplete, e.Name+" ("+e.Status+")")
			}
		}
		if len(incomplete) == 0 {
			incomplete = []string{"scan marked partial"}
		}
		v = append(v, "fail_on_partial: "+strings.Join(incomplete, ", "))
	}
	return v
}
