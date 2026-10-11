package webscan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
)

// Template limits (Section 5.4 and 9 "hostile inputs").
const (
	MaxTemplateBytes = 1 << 20
	MaxRegexLen      = 512
	MaxRegexProgram  = 2000 // compiled RE2 instructions; bounds memory, time is linear anyway
	MaxPathsPerStep  = 16
	MaxStepsPerTpl   = 4
	MaxMatchers      = 16
	MaxWordLen       = 1024
	MaxPOSTBody      = 4096
	MaxUserTemplates = 2000
)

// TemplateIDPattern constrains template identifiers.
var TemplateIDPattern = regexp.MustCompile(`^[a-z0-9-]{3,64}$`)

// PathPattern is the only shape a request path may take: absolute, no
// query, no userinfo, no scheme, nothing that could change the host.
var PathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)

// unsafeTags are refused on safe templates (and on all templates in Phase 2,
// since intrusive templates do not load without --allow-intrusive, which does
// not exist yet).
var unsafeTags = map[string]bool{"unsafe": true, "intrusive": true, "dos": true, "fuzz": true, "fuzzing": true, "bruteforce": true, "brute-force": true, "exploit": true, "rce": true, "dast": true}

// Info is the authored prose of a template.
type Info struct {
	Title      string   `yaml:"title"`
	Severity   string   `yaml:"severity"`
	CWE        string   `yaml:"cwe,omitempty"`
	What       string   `yaml:"what"`
	Why        string   `yaml:"why"`
	Fix        string   `yaml:"fix"`
	References []string `yaml:"references,omitempty"`
	Tags       []string `yaml:"tags,omitempty"`
}

// Matcher is one condition on a response.
type Matcher struct {
	Type            string   `yaml:"type"`                // status | word | regex | header | size
	Status          []int    `yaml:"status,omitempty"`    // status
	Words           []string `yaml:"words,omitempty"`     // word
	Regex           []string `yaml:"regex,omitempty"`     // regex
	Name            string   `yaml:"name,omitempty"`      // header: header name
	Size            []int    `yaml:"size,omitempty"`      // size: body length
	Part            string   `yaml:"part,omitempty"`      // body (default) | header | all
	Condition       string   `yaml:"condition,omitempty"` // and | or (default or) across values
	Negative        bool     `yaml:"negative,omitempty"`
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`

	compiled []*regexp.Regexp
}

// Extractor pulls a value from the response into evidence.
type Extractor struct {
	Type  string   `yaml:"type"` // regex | header
	Regex []string `yaml:"regex,omitempty"`
	Name  string   `yaml:"name,omitempty"`
	Group int      `yaml:"group,omitempty"`

	compiled []*regexp.Regexp
}

// Step is one HTTP request definition.
type Step struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Body              string            `yaml:"body,omitempty"`
	Headers           map[string]string `yaml:"headers,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"` // and | or (default and)
	Matchers          []Matcher         `yaml:"matchers"`
	Extractors        []Extractor       `yaml:"extractors,omitempty"`
}

// Template is one check. Only the `http` protocol exists; strict decoding
// refuses anything else (network, dns, headless, code, ...).
type Template struct {
	ID     string `yaml:"id"`
	Info   Info   `yaml:"info"`
	Safety string `yaml:"safety"`
	HTTP   []Step `yaml:"http"`

	Source string `yaml:"-"` // file name, for diagnostics
}

// RuleID is the finding rule ID for a template.
func (t *Template) RuleID() string { return "web.tpl." + t.ID }

// Rule renders the template prose as a domain.Rule.
func (t *Template) Rule() domain.Rule {
	return domain.Rule{ID: t.RuleID(), Engine: Name, Title: t.Info.Title, Severity: strings.ToLower(t.Info.Severity), CWE: t.Info.CWE,
		WhatItIs: t.Info.What, WhyItMatters: t.Info.Why, HowToFix: t.Info.Fix, References: t.Info.References, Safety: t.Safety, Tags: t.Info.Tags}
}

// ParseTemplate decodes and validates one template document. Decoding is
// strict (unknown fields fail), the input is capped, and every regex must be
// RE2 (Go's engine; no backreferences or lookaround can compile).
func ParseTemplate(b []byte, source string) (*Template, error) {
	if len(b) > MaxTemplateBytes {
		return nil, fmt.Errorf("%s: template exceeds %d bytes", source, MaxTemplateBytes)
	}
	if engine.YAMLDepth(b, engine.MaxNestingDepth) > engine.MaxNestingDepth {
		return nil, fmt.Errorf("%s: template nests deeper than %d levels", source, engine.MaxNestingDepth)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var t Template
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: one template per file", source)
	}
	t.Source = source
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return &t, nil
}

func (t *Template) validate() error {
	if !TemplateIDPattern.MatchString(t.ID) {
		return fmt.Errorf("bad template id %q (want %s)", t.ID, TemplateIDPattern)
	}
	if t.Safety != domain.SafetySafe && t.Safety != domain.SafetyIntrusive {
		return fmt.Errorf("template %s: safety must be %q or %q", t.ID, domain.SafetySafe, domain.SafetyIntrusive)
	}
	if _, ok := domain.ParseSeverity(t.Info.Severity); !ok {
		return fmt.Errorf("template %s: bad severity %q", t.ID, t.Info.Severity)
	}
	if t.Info.Title == "" || t.Info.What == "" || t.Info.Why == "" || t.Info.Fix == "" {
		return fmt.Errorf("template %s: info.title/what/why/fix are required", t.ID)
	}
	for _, tag := range t.Info.Tags {
		if unsafeTags[strings.ToLower(tag)] {
			return fmt.Errorf("template %s: tag %q is not permitted (safe-matcher-only policy)", t.ID, tag)
		}
	}
	for _, ref := range t.Info.References {
		if !strings.HasPrefix(ref, "https://") && !strings.HasPrefix(ref, "http://") {
			return fmt.Errorf("template %s: reference %q must be an http(s) URL", t.ID, ref)
		}
	}
	if len(t.HTTP) == 0 {
		return fmt.Errorf("template %s: at least one http step is required", t.ID)
	}
	if len(t.HTTP) > MaxStepsPerTpl {
		return fmt.Errorf("template %s: more than %d http steps", t.ID, MaxStepsPerTpl)
	}
	for i := range t.HTTP {
		if err := t.HTTP[i].validate(t.Safety); err != nil {
			return fmt.Errorf("template %s step %d: %w", t.ID, i+1, err)
		}
	}
	return nil
}

func (s *Step) validate(safety string) error {
	switch s.Method {
	case http.MethodGet, http.MethodHead:
		if s.Body != "" {
			return errors.New("GET/HEAD steps cannot carry a body")
		}
	case http.MethodPost:
		if safety != domain.SafetyIntrusive {
			return errors.New("POST is only permitted in intrusive templates")
		}
		if len(s.Body) > MaxPOSTBody {
			return fmt.Errorf("POST body exceeds %d bytes", MaxPOSTBody)
		}
	default:
		return fmt.Errorf("method %q not permitted (GET|HEAD|POST)", s.Method)
	}
	if len(s.Path) == 0 || len(s.Path) > MaxPathsPerStep {
		return fmt.Errorf("between 1 and %d paths are required", MaxPathsPerStep)
	}
	for _, p := range s.Path {
		if !PathPattern.MatchString(p) || strings.Contains(p, "//") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
			return fmt.Errorf("path %q not permitted (want %s, no // or ..)", p, PathPattern)
		}
	}
	for k, v := range s.Headers {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "authorization" || lk == "cookie" || lk == "proxy-authorization" || strings.ContainsAny(k+v, "\r\n\x00") {
			return fmt.Errorf("header %q not permitted", k)
		}
	}
	switch s.MatchersCondition {
	case "", "and", "or":
	default:
		return fmt.Errorf("matchers-condition %q (and|or)", s.MatchersCondition)
	}
	if len(s.Matchers) == 0 || len(s.Matchers) > MaxMatchers {
		return fmt.Errorf("between 1 and %d matchers are required", MaxMatchers)
	}
	for i := range s.Matchers {
		if err := s.Matchers[i].compile(); err != nil {
			return fmt.Errorf("matcher %d: %w", i+1, err)
		}
	}
	for i := range s.Extractors {
		if err := s.Extractors[i].compile(); err != nil {
			return fmt.Errorf("extractor %d: %w", i+1, err)
		}
	}
	return nil
}

func (m *Matcher) compile() error {
	switch m.Part {
	case "", "body", "header", "all":
	default:
		return fmt.Errorf("part %q (body|header|all)", m.Part)
	}
	switch m.Condition {
	case "", "and", "or":
	default:
		return fmt.Errorf("condition %q (and|or)", m.Condition)
	}
	switch m.Type {
	case "status":
		if len(m.Status) == 0 {
			return errors.New("status matcher needs status codes")
		}
		for _, c := range m.Status {
			if c < 100 || c > 599 {
				return fmt.Errorf("bad status %d", c)
			}
		}
	case "word":
		if len(m.Words) == 0 {
			return errors.New("word matcher needs words")
		}
		for _, w := range m.Words {
			if w == "" || len(w) > MaxWordLen {
				return fmt.Errorf("word length must be 1..%d", MaxWordLen)
			}
		}
	case "regex":
		res, err := compileRegexes(m.Regex)
		if err != nil {
			return err
		}
		m.compiled = res
	case "header":
		if m.Name == "" || strings.ContainsAny(m.Name, " :\r\n") {
			return errors.New("header matcher needs a valid header name")
		}
		if len(m.Words) == 0 && len(m.Regex) == 0 {
			return errors.New("header matcher needs words or regex")
		}
		res, err := compileRegexes(m.Regex)
		if err != nil {
			return err
		}
		m.compiled = res
	case "size":
		if len(m.Size) == 0 {
			return errors.New("size matcher needs sizes")
		}
	default:
		return fmt.Errorf("type %q (status|word|regex|header|size)", m.Type)
	}
	return nil
}

func (x *Extractor) compile() error {
	switch x.Type {
	case "regex":
		if len(x.Regex) == 0 {
			return errors.New("regex extractor needs regex")
		}
		res, err := compileRegexes(x.Regex)
		if err != nil {
			return err
		}
		for _, re := range res {
			if x.Group < 0 || x.Group > re.NumSubexp() {
				return fmt.Errorf("group %d out of range", x.Group)
			}
		}
		x.compiled = res
	case "header":
		if x.Name == "" || strings.ContainsAny(x.Name, " :\r\n") {
			return errors.New("header extractor needs a valid header name")
		}
	default:
		return fmt.Errorf("type %q (regex|header)", x.Type)
	}
	return nil
}

// compileRegexes compiles with regexp/syntax first so the error names the
// construct, then bounds the compiled program size. Go's regexp is RE2:
// anything that compiles runs in linear time.
func compileRegexes(exprs []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(exprs))
	for _, e := range exprs {
		if e == "" || len(e) > MaxRegexLen {
			return nil, fmt.Errorf("regex length must be 1..%d", MaxRegexLen)
		}
		re, err := syntax.Parse(e, syntax.Perl)
		if err != nil {
			return nil, fmt.Errorf("regex %q is not RE2: %w", e, err)
		}
		prog, err := syntax.Compile(re.Simplify())
		if err != nil {
			return nil, fmt.Errorf("regex %q: %w", e, err)
		}
		if len(prog.Inst) > MaxRegexProgram {
			return nil, fmt.Errorf("regex %q too complex (%d instructions > %d)", e, len(prog.Inst), MaxRegexProgram)
		}
		c, err := regexp.Compile(e)
		if err != nil {
			return nil, fmt.Errorf("regex %q: %w", e, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// Response is what matchers see.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	rawHdrs string
}

func (r *Response) headerText() string {
	if r.rawHdrs == "" {
		var b strings.Builder
		keys := make([]string, 0, len(r.Header))
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range r.Header[k] {
				b.WriteString(k + ": " + v + "\n")
			}
		}
		r.rawHdrs = b.String()
	}
	return r.rawHdrs
}

func (r *Response) part(p string) string {
	switch p {
	case "header":
		return r.headerText()
	case "all":
		return r.headerText() + "\n" + string(r.Body)
	}
	return string(r.Body)
}

// Match evaluates one matcher.
func (m *Matcher) Match(r *Response) bool {
	ok := m.match(r)
	if m.Negative {
		return !ok
	}
	return ok
}

func (m *Matcher) match(r *Response) bool {
	and := m.Condition == "and"
	switch m.Type {
	case "status":
		for _, c := range m.Status {
			if r.Status == c {
				return true
			}
		}
		return false
	case "size":
		for _, s := range m.Size {
			if len(r.Body) == s {
				return true
			}
		}
		return false
	case "word":
		text := r.part(m.Part)
		if m.CaseInsensitive {
			text = strings.ToLower(text)
		}
		return allOrAny(and, len(m.Words), func(i int) bool {
			w := m.Words[i]
			if m.CaseInsensitive {
				w = strings.ToLower(w)
			}
			return strings.Contains(text, w)
		})
	case "regex":
		text := r.part(m.Part)
		return allOrAny(and, len(m.compiled), func(i int) bool { return m.compiled[i].MatchString(text) })
	case "header":
		vals := r.Header.Values(m.Name)
		if len(vals) == 0 {
			return false
		}
		joined := strings.Join(vals, "\n")
		if len(m.Words) > 0 {
			if !allOrAny(and, len(m.Words), func(i int) bool {
				if m.CaseInsensitive {
					return strings.Contains(strings.ToLower(joined), strings.ToLower(m.Words[i]))
				}
				return strings.Contains(joined, m.Words[i])
			}) {
				return false
			}
		}
		if len(m.compiled) > 0 {
			return allOrAny(and, len(m.compiled), func(i int) bool { return m.compiled[i].MatchString(joined) })
		}
		return true
	}
	return false
}

func allOrAny(and bool, n int, f func(int) bool) bool {
	for i := 0; i < n; i++ {
		if f(i) {
			if !and {
				return true
			}
		} else if and {
			return false
		}
	}
	return and
}

// Extract returns the extracted strings (deduplicated, capped).
func (x *Extractor) Extract(r *Response) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] && len(out) < 8 {
			seen[s] = true
			out = append(out, s)
		}
	}
	switch x.Type {
	case "header":
		for _, v := range r.Header.Values(x.Name) {
			add(v)
		}
	case "regex":
		text := string(r.Body)
		for _, re := range x.compiled {
			for _, m := range re.FindAllStringSubmatch(text, 8) {
				if x.Group < len(m) {
					add(m[x.Group])
				}
			}
		}
	}
	return out
}

// Matches evaluates a step's matchers under matchers-condition.
func (s *Step) Matches(r *Response) bool {
	and := s.MatchersCondition != "or"
	return allOrAny(and, len(s.Matchers), func(i int) bool { return s.Matchers[i].Match(r) })
}

// LoadDir reads every *.yaml/*.yml in a directory (not recursive; symlinks
// are not followed). Errors are collected per file so `templates validate`
// can list them all.
func LoadDir(dir string) ([]*Template, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{err}
	}
	var out []*Template
	var errs []error
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		n++
		if n > MaxUserTemplates {
			errs = append(errs, fmt.Errorf("%s: more than %d templates", dir, MaxUserTemplates))
			break
		}
		b, err := readCapped(filepath.Join(dir, name))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		t, err := ParseTemplate(b, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, t)
	}
	return out, errs
}

// LoadFS loads the embedded templates; any error is a programmer error.
func LoadFS(fsys fs.FS, dir string) ([]*Template, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []*Template
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		t, err := ParseTemplate(b, e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxTemplateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxTemplateBytes {
		return nil, fmt.Errorf("template exceeds %d bytes", MaxTemplateBytes)
	}
	return b, nil
}

// HashTemplates returns a SHA-256 over the canonical YAML of every template
// in order, so the audit trail records exactly which checks ran.
func HashTemplates(tpls []*Template) string {
	var b bytes.Buffer
	for _, t := range tpls {
		out, err := yaml.Marshal(t)
		if err != nil {
			out = []byte(t.ID) // cannot happen for a parsed template; degrade to the ID
		}
		b.Write(out)
		b.WriteByte(0)
	}
	return domain.SHA256Hex(b.String())
}

// Merge combines embedded and user templates; a user template with the same
// ID replaces the embedded one (so users can tune prose). Duplicate IDs
// within the user set are an error.
func Merge(embedded, user []*Template) ([]*Template, error) {
	byID := map[string]*Template{}
	var order []string
	for _, t := range embedded {
		byID[t.ID] = t
		order = append(order, t.ID)
	}
	seen := map[string]bool{}
	for _, t := range user {
		if seen[t.ID] {
			return nil, fmt.Errorf("duplicate template id %q in user templates", t.ID)
		}
		seen[t.ID] = true
		if _, ok := byID[t.ID]; !ok {
			order = append(order, t.ID)
		}
		byID[t.ID] = t
	}
	out := make([]*Template, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}
