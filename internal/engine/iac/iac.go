// Package iac checks infrastructure-as-code files: Dockerfiles (own line
// parser), Kubernetes manifests (strict YAML, depth and size capped) and
// Terraform (HCL via hashicorp/hcl). Rules are Go functions over the parsed
// structure; their plain-English text lives in rules/iac.yaml. Nothing is
// ever executed: no `docker build`, no `terraform plan`, no provider calls.
package iac

import (
	"context"
	"embed"
	"fmt"
	"path"
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
const Name = "iac"

// MaxIaCFileBytes caps one IaC file (manifests and .tf files are small).
const MaxIaCFileBytes = 1 << 20

// secretKeyRe is what makes an ENV/ARG/variable/env name credential-like.
var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key|credential)`)

// Engine implements engine.Engine.
type Engine struct {
	rules engine.RuleSet
}

// New loads the rule prose and checks every Go rule has it.
func New() (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	for _, id := range allRuleIDs() {
		rs.MustGet(id)
	}
	return &Engine{rules: rs}, nil
}

// RuleFileSkipped is the coverage note emitted once per scan when files
// were skipped unparsed because they nest deeper than engine.MaxNestingDepth.
const RuleFileSkipped = "iac.file-skipped-too-complex"

func allRuleIDs() []string {
	var out []string
	out = append(out, dockerRuleIDs...)
	out = append(out, k8sRuleIDs...)
	out = append(out, terraformRuleIDs...)
	out = append(out, RuleFileSkipped)
	return out
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Supports path targets.
func (e *Engine) Supports(t domain.Target) bool { return t.Type == domain.TargetPath }

// kind classifies a file by name (Kubernetes is confirmed by content).
type kind int

const (
	kindNone kind = iota
	kindDockerfile
	kindYAML
	kindTerraform
)

func classify(rel string) kind {
	base := path.Base(rel)
	switch {
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".dockerfile") || strings.HasSuffix(base, ".Dockerfile"):
		return kindDockerfile
	case strings.HasSuffix(base, ".tf"):
		return kindTerraform
	case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
		return kindYAML
	}
	return kindNone
}

// Plan implements engine.Engine.
func (e *Engine) Plan(ctx context.Context, t domain.Target, _ engine.Options) (engine.Plan, error) {
	var docker, yamls, tf int
	_, err := engine.WalkFiles(ctx, t.Value, func(rel string, content []byte) error {
		switch classify(rel) {
		case kindDockerfile:
			docker++
		case kindTerraform:
			tf++
		case kindYAML:
			if looksLikeK8s(content) {
				yamls++
			}
		}
		return nil
	})
	if err != nil {
		return engine.Plan{}, err
	}
	return engine.Plan{Summary: fmt.Sprintf("%d Dockerfile(s), %d Kubernetes manifest(s), %d Terraform file(s) checked against %d rules (no execution)", docker, yamls, tf, len(allRuleIDs())), EstDuration: time.Second}, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	em := &emitter{e: e, assetKey: t.AssetKey(), key: o.SecretKey, red: o.Redactor, emit: emit}
	if em.red == nil {
		em.red = safety.NewRedactor()
	}
	tf := &terraformModule{}
	_, err := engine.WalkFiles(ctx, t.Value, func(rel string, content []byte) error {
		if len(content) > MaxIaCFileBytes {
			return nil
		}
		switch classify(rel) {
		case kindDockerfile:
			return checkDockerfile(rel, content, em)
		case kindYAML:
			if looksLikeK8s(content) {
				return checkKubernetes(rel, content, em)
			}
		case kindTerraform:
			if !tf.add(rel, content) {
				em.skipped = append(em.skipped, rel)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := checkTerraform(ctx, tf, em); err != nil {
		return err
	}
	return em.skippedNote(t.Value)
}

// emitter builds findings for rules at file:line locations.
type emitter struct {
	e        *Engine
	assetKey string
	key      []byte
	red      *safety.Redactor
	emit     engine.EmitFunc
	skipped  []string // files skipped unparsed as too deeply nested
}

// skippedNote emits RuleFileSkipped once, naming how many files (and the
// first few) were not checked, so coverage gaps are visible in the report.
func (em *emitter) skippedNote(root string) error {
	if len(em.skipped) == 0 {
		return nil
	}
	names := em.skipped
	if len(names) > 5 {
		names = names[:5]
	}
	f := em.finding(RuleFileSkipped, root, 0, domain.Confirmed)
	f.Evidence = []domain.Evidence{em.red.TextEvidence("file", root, fmt.Sprintf("%d file(s) nest deeper than %d levels and were skipped unparsed: %s", len(em.skipped), engine.MaxNestingDepth, strings.Join(names, ", ")))}
	return em.emit(f)
}

func (em *emitter) finding(id, file string, line int, conf domain.Confidence) domain.Finding {
	loc := file
	if line > 0 {
		loc = fmt.Sprintf("%s:%d", file, line)
	}
	return em.e.rules.NewFinding(id, em.assetKey, loc, conf)
}

// rule emits a structural finding with a short excerpt as evidence (the
// excerpt is redacted and control-stripped like any other text).
func (em *emitter) rule(id, file string, line int, excerpt string) error {
	f := em.finding(id, file, line, domain.Firm)
	f.Evidence = []domain.Evidence{em.red.TextEvidence("file", f.Location, excerpt)}
	return em.emit(f)
}

// secret emits a credential finding: the value is masked before Evidence
// exists and fingerprinted with the per-install key when available (the
// masked form is hashed otherwise, so a report never enables an offline
// guess of the raw value).
func (em *emitter) secret(id, file string, line int, name, raw string) error {
	f := em.finding(id, file, line, domain.Firm)
	var ev domain.Evidence
	if len(em.key) > 0 {
		ev = safety.SecretEvidence(em.key, "file", f.Location, raw)
	} else {
		m := safety.Mask(raw)
		ev = domain.Evidence{Kind: "file", Location: f.Location, Redacted: m, Hash: domain.SHA256Hex(m)}
	}
	ev.Redacted = safety.StripControl(name) + "=" + ev.Redacted
	f.Evidence = []domain.Evidence{ev}
	// Like secrets, the location carries the evidence hash so moving the
	// line keeps the fingerprint (domain.NormaliseLocation strips the line).
	f.Location += "#" + ev.Hash[:16]
	f.Fingerprint = domain.Fingerprint(f.RuleID, em.assetKey, f.Location)
	return em.emit(f)
}

// isSecretAssignment reports whether name looks like a credential and value
// is a literal worth reporting (not a variable reference or placeholder).
func isSecretAssignment(name, value string) bool {
	if !secretKeyRe.MatchString(name) || len(value) < 4 {
		return false
	}
	v := strings.TrimSpace(value)
	if v == "" || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "<") || strings.HasPrefix(v, "%") {
		return false
	}
	switch strings.ToLower(v) {
	case "changeme", "change_me", "password", "secret", "example", "placeholder", "todo", "null", "none", "true", "false", "xxx", "xxxx":
		return false
	}
	return true
}
