package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/gerald/scnr/internal/domain"
)

// RuleIDPattern constrains rule identifiers.
var RuleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,80}$`)

// MaxRuleFileBytes caps one embedded rules file.
const MaxRuleFileBytes = 1 << 20

// RuleSet is a loaded set of rules keyed by ID.
type RuleSet map[string]domain.Rule

// LoadRules reads every *.yaml under dir in fsys. Each file holds a YAML
// stream of Rule documents. Decoding is strict (unknown fields fail).
func LoadRules(fsys fs.FS, dir, engine string) (RuleSet, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	rs := RuleSet{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		if len(b) > MaxRuleFileBytes {
			return nil, fmt.Errorf("%s: rules file exceeds %d bytes", e.Name(), MaxRuleFileBytes)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		for {
			var r domain.Rule
			err := dec.Decode(&r)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			if err := validateRule(r, engine); err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			if _, dup := rs[r.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate rule id %q", e.Name(), r.ID)
			}
			rs[r.ID] = r
		}
	}
	return rs, nil
}

func validateRule(r domain.Rule, engine string) error {
	if !RuleIDPattern.MatchString(r.ID) {
		return fmt.Errorf("bad rule id %q", r.ID)
	}
	if r.Engine != engine {
		return fmt.Errorf("rule %s: engine %q != %q", r.ID, r.Engine, engine)
	}
	if _, ok := domain.ParseSeverity(r.Severity); !ok {
		return fmt.Errorf("rule %s: bad severity %q", r.ID, r.Severity)
	}
	if r.Safety != domain.SafetySafe && r.Safety != domain.SafetyIntrusive {
		return fmt.Errorf("rule %s: safety must be %q or %q", r.ID, domain.SafetySafe, domain.SafetyIntrusive)
	}
	if r.Title == "" || r.WhatItIs == "" || r.WhyItMatters == "" || r.HowToFix == "" {
		return fmt.Errorf("rule %s: title/what/why/fix are required", r.ID)
	}
	return nil
}

// MustGet returns the rule or panics; rules are embedded so absence is a
// programmer error caught by tests.
func (rs RuleSet) MustGet(id string) domain.Rule {
	r, ok := rs[id]
	if !ok {
		panic("missing rule " + id)
	}
	return r
}

// NewFinding builds a finding from a rule for an asset and location.
func (rs RuleSet) NewFinding(id, assetKey, location string, conf domain.Confidence) domain.Finding {
	f := domain.Finding{AssetKey: assetKey, Location: location, Confidence: conf, Status: domain.StatusOpen}
	rs.MustGet(id).Apply(&f)
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, location)
	return f
}
