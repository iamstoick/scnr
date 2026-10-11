package adapter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/safety"
)

// StreamArray decodes a top-level JSON object and calls fn once per element
// of the array held under key, streaming so a 256 MiB report never has to
// be in memory at once. Other top-level values are skipped. A malformed
// element is counted and skipped; parsing continues. Returns the number of
// bad elements and the first fatal (syntax) error.
func StreamArray(r io.Reader, key string, fn func(dec *json.Decoder) error) (bad int, err error) {
	dec := json.NewDecoder(r)
	if err := openDelim(dec, '{', "object"); err != nil {
		return 0, err
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return bad, fmt.Errorf("json: %w", err)
		}
		k, _ := kt.(string)
		if k != key {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return bad, fmt.Errorf("json: %w", err)
			}
			continue
		}
		tok, err := dec.Token()
		if err != nil {
			return bad, fmt.Errorf("json: %w", err)
		}
		if tok == nil {
			continue // "key": null
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return bad, fmt.Errorf("json: %q is not an array", key)
		}
		n, err := streamElements(dec, fn)
		bad += n
		if err != nil {
			return bad, err
		}
		if _, err := dec.Token(); err != nil { // closing ]
			return bad, fmt.Errorf("json: %w", err)
		}
	}
	return bad, nil
}

// StreamTopLevelArray is StreamArray for output whose top-level value is
// the array itself (prowler's OCSF report): fn is called once per element
// with the same skip/count semantics.
func StreamTopLevelArray(r io.Reader, fn func(dec *json.Decoder) error) (bad int, err error) {
	dec := json.NewDecoder(r)
	if err := openDelim(dec, '[', "array"); err != nil {
		return 0, err
	}
	if bad, err = streamElements(dec, fn); err != nil {
		return bad, err
	}
	if _, err := dec.Token(); err != nil { // closing ]
		return bad, fmt.Errorf("json: %w", err)
	}
	return bad, nil
}

// openDelim consumes the top-level opening delimiter and fails when the
// value is not of the expected kind.
func openDelim(dec *json.Decoder, want json.Delim, kind string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return errors.New("json: top-level value is not an " + kind)
	}
	return nil
}

// streamElements drives fn over the elements of the array dec is
// positioned inside, stopping at the closing bracket (not consumed).
func streamElements(dec *json.Decoder, fn func(dec *json.Decoder) error) (bad int, err error) {
	for dec.More() {
		if err := fn(dec); err != nil {
			var se *json.SyntaxError
			if errors.As(err, &se) || errors.Is(err, io.ErrUnexpectedEOF) {
				return bad, fmt.Errorf("json: %w", err)
			}
			if errors.Is(err, ErrSkipElement) {
				bad++
				continue
			}
			return bad, err
		}
	}
	return bad, nil
}

// ErrSkipElement is returned by StreamArray callbacks for an element that
// decoded but failed validation; it is counted, not fatal.
var ErrSkipElement = errors.New("skip element")

// DecodeElement decodes the next array element into v; a type mismatch
// (e.g. a string where an object is expected) becomes ErrSkipElement so the
// rest of the array is still parsed.
func DecodeElement(dec *json.Decoder, v any) error {
	err := dec.Decode(v)
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return ErrSkipElement
	}
	return err
}

// BadCount formats the "N elements were skipped" error adapters return
// after emitting every good finding.
func BadCount(tool string, bad int) error {
	if bad == 0 {
		return nil
	}
	return fmt.Errorf("%s output: %d element(s) were malformed and were skipped", tool, bad)
}

var (
	cveRe  = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cweRe  = regexp.MustCompile(`^(CWE-)?\d{1,5}$`)
	vulnRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{2,63}$`)
)

// maxLocationBytes bounds a tool-reported path.
const maxLocationBytes = 1024

// CVE returns the upper-cased ID when it is a CVE, else "".
func CVE(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if cveRe.MatchString(s) {
		return s
	}
	return ""
}

// CWE normalises "79" / "CWE-79" to "CWE-79", else "".
func CWE(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !cweRe.MatchString(s) {
		return ""
	}
	return "CWE-" + strings.TrimPrefix(s, "CWE-")
}

// ValidVulnID accepts GHSA-/CVE-/distro advisory IDs.
func ValidVulnID(s string) bool { return vulnRe.MatchString(s) }

// RelLocation turns a tool-reported path into the repo-relative form native
// engines use: the scan root prefix removed, leading "./" and "/" dropped,
// backslashes normalised. ok is false for traversal or absolute paths that
// do not sit under root.
func RelLocation(root, p string) (string, bool) {
	p = strings.ReplaceAll(safety.StripControl(p), "\\", "/")
	if p == "" || len(p) > maxLocationBytes {
		return "", false
	}
	if root != "" {
		r := strings.TrimSuffix(strings.ReplaceAll(root, "\\", "/"), "/")
		if p == r {
			return ".", true
		}
		if strings.HasPrefix(p, r+"/") {
			p = p[len(r)+1:]
		}
	}
	p = strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
	if p == "" || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return "", false
	}
	return p, true
}

// Severity maps tool severity words (CRITICAL/HIGH/MEDIUM/LOW/NEGLIGIBLE/
// UNKNOWN/INFO, semgrep ERROR/WARNING/INFO) to domain.Severity.
func Severity(s string) (domain.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return domain.Critical, true
	case "HIGH", "ERROR":
		return domain.High, true
	case "MEDIUM", "MODERATE", "WARNING":
		return domain.Medium, true
	case "LOW":
		return domain.Low, true
	case "INFO", "INFORMATIONAL", "NEGLIGIBLE", "UNKNOWN", "":
		return domain.Info, true
	}
	return domain.Info, false
}

// Vuln is the tool-independent view of one package vulnerability that
// trivy and grype parsers fill in; Finding turns it into the shared
// sca.osv.<id>@<purl> scheme so all three SCA sources dedupe.
type Vuln struct {
	ID          string   // primary advisory ID
	Aliases     []string // related IDs (CVEs preferred for the rule ID)
	PURL        string   // tool PURL (normalised here) or ""
	Ecosystem   string   // fallback when PURL is absent, OSV name
	Name        string
	Version     string
	Fixed       string
	Severity    string
	Title       string
	Description string
	References  []string
	CVSSVector  string
	CVSSScore   float64
	CWE         string
	Location    string // repo-relative file or OS db path
}

// MaxRefs kept per finding.
const MaxRefs = 10

// URLRefs keeps the first MaxRefs distinct http(s) references, control
// characters stripped and over-long values dropped. Tools repeat the
// primary URL in their reference lists; the report shows each once.
func URLRefs(refs ...string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, r := range refs {
		r = strings.TrimSpace(safety.StripControl(r))
		if (strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://")) && len(r) < 512 && !seen[r] && len(out) < MaxRefs {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// Finding builds the shared-scheme finding. rules supplies the
// sca.vulnerable-dependency prose; label names the tool in evidence.
func (v *Vuln) Finding(rules interface{ MustGet(string) domain.Rule }, red *safety.Redactor, assetKey, label string) (domain.Finding, bool) {
	if !ValidVulnID(v.ID) || v.Name == "" || v.Version == "" || v.Location == "" {
		return domain.Finding{}, false
	}
	purl, ok := sca.NormalizePURL(v.PURL)
	if !ok {
		if v.Ecosystem == "" {
			return domain.Finding{}, false
		}
		purl = sca.Package{Ecosystem: v.Ecosystem, Name: v.Name, Version: v.Version}.PURL()
	}
	sev, ok := Severity(v.Severity)
	if !ok {
		return domain.Finding{}, false
	}
	name, version := red.Clean(v.Name, 200), red.Clean(v.Version, 100)
	f := domain.Finding{AssetKey: assetKey, Location: v.Location, Confidence: domain.Firm, Status: domain.StatusOpen, Severity: sev}
	rules.MustGet("sca.vulnerable-dependency").Apply(&f)
	f.Severity = sev
	f.RuleID = sca.VulnRuleID(v.ID, v.Aliases, purl)
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, v.Location)
	title := red.Clean(v.Title, 200)
	if title == "" {
		title = v.ID
	}
	f.Title = fmt.Sprintf("%s %s: %s", name, version, title)
	desc := red.Clean(v.Description, 1000)
	if desc == "" {
		desc = "no description from " + label
	}
	f.WhatItIs = fmt.Sprintf("%s version %s (from %s) is affected by %s. %s (description from %s)", name, version, v.Location, v.ID, desc, label)
	f.CVEs = []string{}
	seen := map[string]bool{}
	for _, a := range append([]string{v.ID}, v.Aliases...) {
		if c := CVE(a); c != "" && !seen[c] {
			seen[c] = true
			f.CVEs = append(f.CVEs, c)
		}
	}
	f.CWE = CWE(v.CWE)
	f.References = URLRefs(v.References...)
	if vec := safety.StripControl(v.CVSSVector); strings.HasPrefix(vec, "CVSS:3") && v.CVSSScore > 0 && v.CVSSScore <= 10 {
		f.CVSS = &domain.CVSS{Vector: vec, Score: v.CVSSScore}
	}
	if fixed := red.Clean(v.Fixed, 100); fixed != "" {
		f.HowToFix = fmt.Sprintf("Upgrade `%s` to `%s` or later.", name, fixed)
	} else {
		f.HowToFix = fmt.Sprintf("No fixed version is reported by %s for `%s`. Check the references for mitigations and watch for a release.", label, name)
	}
	f.Evidence = []domain.Evidence{sca.PackageEvidence(label, v.Location, red.Clean(v.Ecosystem, 40), name, version, purl)}
	return f, true
}

// ReadLine returns the next line of br without its terminator. A line
// longer than max is consumed to its end and reported as tooLong with no
// bytes retained, so a hostile stream cannot make the caller hold more
// than max bytes; the caller decides whether that is a skip (tool output)
// or a hard error (a signed bundle). err is io.EOF on the last line.
func ReadLine(br *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, rerr := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > max {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(rerr, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			return nil, true, rerr
		}
		return bytes.TrimRight(buf, "\r\n"), false, rerr
	}
}
