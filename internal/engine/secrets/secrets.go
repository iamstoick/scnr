// Package secrets detects credentials in a working tree with own-authored
// regex rules plus a Shannon-entropy heuristic. Redaction happens here,
// before any Evidence exists; raw values never leave this package.
package secrets

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
)

//go:embed rules/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "secrets"

const (
	entropyThreshold = 4.0
	entropyMinLen    = 20
	maxLineBytes     = 4096
)

// pattern is one detection rule. group is the capture group holding the
// secret value (0 = whole match).
type pattern struct {
	rule  string
	re    *regexp.Regexp
	group int
	// verify, if set, filters matches (e.g. entropy on generic values).
	verify func(string) bool
}

var patterns = []pattern{
	{rule: "secret.aws-access-key", re: regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`), group: 1},
	{rule: "secret.aws-secret-key", re: regexp.MustCompile(`(?i)aws[^\n]{0,30}?(?:secret|key)[^\n]{0,10}?['"]?([0-9a-zA-Z/+]{40})['"]?`), group: 1, verify: func(s string) bool { return entropy(s) > 3.5 }},
	{rule: "secret.gcp-service-account", re: regexp.MustCompile(`"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY-----[^"]+)"`), group: 1},
	{rule: "secret.github-token", re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`), group: 1},
	{rule: "secret.gitlab-token", re: regexp.MustCompile(`\b(glpat-[A-Za-z0-9\-_]{20,})\b`), group: 1},
	{rule: "secret.slack-token", re: regexp.MustCompile(`(xox[baprs]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,})`), group: 1},
	{rule: "secret.stripe-key", re: regexp.MustCompile(`\b([sr]k_(?:live|test)_[A-Za-z0-9]{16,})\b`), group: 1},
	{rule: "secret.twilio-key", re: regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), group: 1},
	{rule: "secret.google-api-key", re: regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`), group: 1},
	{rule: "secret.private-key", re: regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)`), group: 1},
	{rule: "secret.jwt", re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`), group: 1},
	{rule: "secret.url-credentials", re: regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^/\s:@'"]+:([^/\s@'"]{4,})@[^\s'"]+`), group: 1, verify: func(s string) bool {
		return !isPlaceholder(s)
	}},
	{rule: "secret.generic-password", re: regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]`), group: 1, verify: func(s string) bool {
		return !isPlaceholder(s) && entropy(s) >= 3.0
	}},
}

var quotedRe = regexp.MustCompile(`['"]([A-Za-z0-9+/=_\-]{20,})['"]`)

var placeholderRe = regexp.MustCompile(`(?i)^(\$\{?[a-z_]+\}?|<[^>]+>|\{\{.*\}\}|%[a-z_]+%|x+|\*+|change[_-]?me|password|secret|example|placeholder|your[_-].*|todo|null|none|undefined|true|false|\.\.\.)$`)

func isPlaceholder(s string) bool { return placeholderRe.MatchString(s) }

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Engine implements engine.Engine.
type Engine struct {
	rules engine.RuleSet
}

// New loads the embedded rule prose.
func New() (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	for _, p := range patterns {
		rs.MustGet(p.rule)
	}
	return &Engine{rules: rs}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Supports path targets only.
func (e *Engine) Supports(t domain.Target) bool { return t.Type == domain.TargetPath }

// Plan implements engine.Engine.
func (e *Engine) Plan(ctx context.Context, t domain.Target, _ engine.Options) (engine.Plan, error) {
	n := 0
	st, err := engine.WalkFiles(ctx, t.Value, func(string, []byte) error { n++; return nil })
	if err != nil {
		return engine.Plan{}, err
	}
	return engine.Plan{Summary: fmt.Sprintf("%d text files scanned for %d secret patterns (working tree only, no git history)", st.Files, len(patterns)+1),
		EstDuration: time.Duration(st.Files/200+1) * time.Second}, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	if len(o.SecretKey) == 0 {
		return errors.New("secrets requires the per-install secret key for evidence fingerprints")
	}
	assetKey := t.AssetKey()
	_, err := engine.WalkFiles(ctx, t.Value, func(rel string, content []byte) error {
		return e.scanFile(rel, content, assetKey, o.SecretKey, emit)
	})
	return err
}

// Match is one detected secret, before it becomes a finding.
type Match struct {
	Rule string
	Line int
	Raw  string // only ever held in memory within this package
}

// ScanContent finds secrets in content. Exported for tests and fuzzing.
func ScanContent(content []byte) []Match {
	var out []Match
	seen := map[string]bool{}
	line := 1
	for len(content) > 0 {
		end := bytes.IndexByte(content, '\n')
		var l string
		if end < 0 {
			l = string(content)
			content = nil
		} else {
			l = string(content[:end])
			content = content[end+1:]
		}
		if len(l) > maxLineBytes {
			l = l[:maxLineBytes]
		}
		for _, p := range patterns {
			for _, m := range p.re.FindAllStringSubmatch(l, -1) {
				val := m[p.group]
				if p.verify != nil && !p.verify(val) {
					continue
				}
				key := p.rule + "\x00" + val
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Match{Rule: p.rule, Line: line, Raw: val})
			}
		}
		for _, m := range quotedRe.FindAllStringSubmatch(l, -1) {
			val := m[1]
			if len(val) < entropyMinLen || entropy(val) < entropyThreshold || looksLikeHashOrB64Padding(val) {
				continue
			}
			key := "entropy\x00" + val
			if seen[key] || coveredBySpecific(seen, val) {
				continue
			}
			seen[key] = true
			out = append(out, Match{Rule: "secret.generic-high-entropy", Line: line, Raw: val})
		}
		line++
	}
	return out
}

// coveredBySpecific suppresses the entropy rule when a specific rule already
// matched the same value.
func coveredBySpecific(seen map[string]bool, val string) bool {
	for k := range seen {
		if strings.HasSuffix(k, "\x00"+val) && !strings.HasPrefix(k, "entropy") {
			return true
		}
	}
	return false
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{32,}$|^[0-9A-F]{32,}$`)

// looksLikeHashOrB64Padding filters pure hex digests (git SHAs, checksums),
// which are high-entropy but not secrets.
func looksLikeHashOrB64Padding(s string) bool {
	return hexRe.MatchString(s)
}

func (e *Engine) scanFile(rel string, content []byte, assetKey string, key []byte, emit engine.EmitFunc) error {
	for _, m := range ScanContent(content) {
		ev := safety.SecretEvidence(key, "file", fmt.Sprintf("%s:%d", rel, m.Line), m.Raw)
		// Location carries the evidence hash so moving the secret within the
		// file keeps the same fingerprint (domain.NormaliseLocation).
		loc := fmt.Sprintf("%s:%d#%s", rel, m.Line, ev.Hash[:16])
		conf := domain.Firm
		if m.Rule == "secret.generic-high-entropy" || m.Rule == "secret.generic-password" {
			conf = domain.Tentative
		}
		f := e.rules.NewFinding(m.Rule, assetKey, loc, conf)
		f.Evidence = []domain.Evidence{ev}
		if err := emit(f); err != nil {
			return err
		}
	}
	return nil
}
