// Package domain holds the core types shared by every scnr package:
// targets, assets, findings, scans and rules. It has no dependencies on
// other internal packages so that engines, store and reporters can all
// import it without cycles.
package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// TargetType classifies what a user pointed scnr at.
type TargetType string

const (
	TargetURL   TargetType = "url"
	TargetHost  TargetType = "host"
	TargetCIDR  TargetType = "cidr"
	TargetPath  TargetType = "path"
	TargetImage TargetType = "image"
	TargetCloud TargetType = "cloud"
)

// Target is a normalised user input.
type Target struct {
	Raw      string            `json:"raw"`
	Type     TargetType        `json:"type"`
	Value    string            `json:"value"`
	Hostname string            `json:"hostname,omitempty"`
	Public   bool              `json:"public"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// AssetKey returns the stable natural key for the asset this target maps to.
func (t Target) AssetKey() string {
	switch t.Type {
	case TargetURL:
		return "url:" + t.Value
	case TargetPath:
		return "repo:" + t.Value
	case TargetImage:
		return "image:" + t.Value
	case TargetCloud:
		return "aws:" + strings.TrimPrefix(t.Value, "aws://")
	default:
		return "host:" + t.Value
	}
}

// Asset is a thing that was scanned or discovered.
type Asset struct {
	ID        string            `json:"id"`
	Key       string            `json:"key"`
	Type      TargetType        `json:"type"`
	Name      string            `json:"name"`
	Public    bool              `json:"public"`
	Labels    map[string]string `json:"labels"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// Severity as reported by the rule or upstream source.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity maps a lower/upper-case name to a Severity; ok is false for
// unrecognised names.
func ParseSeverity(s string) (Severity, bool) {
	for i, n := range severityNames {
		if strings.EqualFold(n, s) {
			return Severity(i), true
		}
	}
	return Info, false
}

// Confidence that a finding is real.
type Confidence int

const (
	Tentative Confidence = iota
	Firm
	Confirmed
)

func (c Confidence) String() string {
	switch c {
	case Tentative:
		return "tentative"
	case Firm:
		return "firm"
	case Confirmed:
		return "confirmed"
	}
	return "unknown"
}

// Status is the lifecycle state of a finding.
type Status string

const (
	StatusOpen       Status = "open"
	StatusFixed      Status = "fixed"
	StatusAccepted   Status = "accepted"
	StatusSuppressed Status = "suppressed"
)

// Evidence limits (Section 3).
const (
	MaxEvidencePerFinding = 10
	MaxEvidenceBytes      = 4096
)

// Evidence is a redacted excerpt supporting a finding. Raw content is never
// stored; callers must redact before constructing one (see safety.Redactor).
type Evidence struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Redacted string `json:"redacted"`
	Hash     string `json:"hash"`
}

// CVSS carries a vector and its base score.
type CVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
}

// Finding is one vulnerability or weakness.
type Finding struct {
	ID           string     `json:"id"`
	Fingerprint  string     `json:"fingerprint"`
	ScanID       string     `json:"scan_id"`
	AssetKey     string     `json:"asset_key"`
	RuleID       string     `json:"rule_id"`
	Engine       string     `json:"engine"`
	Title        string     `json:"title"`
	Severity     Severity   `json:"severity"`
	Confidence   Confidence `json:"confidence"`
	WhatItIs     string     `json:"what_it_is"`
	WhyItMatters string     `json:"why_it_matters"`
	HowToFix     string     `json:"how_to_fix"`
	Location     string     `json:"location"`
	Evidence     []Evidence `json:"evidence"`
	CVEs         []string   `json:"cves"`
	CWE          string     `json:"cwe,omitempty"`
	CVSS         *CVSS      `json:"cvss,omitempty"`
	EPSS         *float64   `json:"epss,omitempty"`
	KEV          bool       `json:"kev"`
	Risk         int        `json:"risk"`
	References   []string   `json:"references"`
	Status       Status     `json:"status"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
}

// EngineRun records how one engine fared in a scan.
type EngineRun struct {
	Name     string        `json:"name"`
	Version  string        `json:"version,omitempty"`
	Status   string        `json:"status"` // ok | failed | skipped: <reason> | partial: <reason>
	Duration time.Duration `json:"duration_ms"`
	Error    string        `json:"error,omitempty"`
}

// Consent methods recorded on a scan.
const (
	ConsentInteractive  = "interactive"
	ConsentDNSTXT       = "dns-txt"
	ConsentWellKnown    = "well-known"
	ConsentPrivateRange = "private-range"
	ConsentLocal        = "local" // path targets: acknowledgment only
	// ConsentCloudAllowlist: the confirmed cloud account id is listed in
	// cloud.<provider>.accounts of the scope file.
	ConsentCloudAllowlist = "cloud-allowlist"
)

// ConsentRecord says how authorisation for a scan was established.
type ConsentRecord struct {
	Method string    `json:"method"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// PostureScore summarises a scan (Section 7).
type PostureScore struct {
	Score    int            `json:"score"`
	Grade    string         `json:"grade"`
	Counts   map[string]int `json:"counts"` // by risk bucket
	KEVOpen  bool           `json:"kev_open"`
	Partial  bool           `json:"partial"`
	Explain  string         `json:"explain,omitempty"`
	TopFixes []Finding      `json:"-"`
}

// Scan is one run of scnr.
type Scan struct {
	ID            string        `json:"id"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Profile       string        `json:"profile"`
	Targets       []Target      `json:"targets"`
	TargetSetHash string        `json:"target_set_hash"`
	Engines       []EngineRun   `json:"engines"`
	Consent       ConsentRecord `json:"consent"`
	ScopeHash     string        `json:"scope_hash"`
	Partial       bool          `json:"partial"`
	Posture       PostureScore  `json:"posture"`
	ExitCode      int           `json:"exit_code"`
	// Schedule names the schedule that ran this scan (daemon only).
	Schedule string `json:"schedule,omitempty"`
	// Intrusive records the active-checks (4d) outcome. Ran is false for
	// scans that never ran intrusive checks (including every scan stored
	// before 4d, whose meta has no intrusive key).
	Intrusive IntrusiveOutcome `json:"intrusive"`
}

// IntrusiveOutcome is stored as scans.meta.intrusive
// ({targets:[…], probes:n}) and shown by reports as the "Active checks
// ran" banner.
type IntrusiveOutcome struct {
	Ran     bool     `json:"ran"`
	Targets []string `json:"targets,omitempty"`
	Probes  int      `json:"probes,omitempty"`
}

// Safety values a Rule may carry. There is deliberately no third value.
const (
	SafetySafe      = "safe"
	SafetyIntrusive = "intrusive"
)

// Rule is the authored description of a check, including plain-English text.
type Rule struct {
	ID           string   `yaml:"id" json:"id"`
	Engine       string   `yaml:"engine" json:"engine"`
	Title        string   `yaml:"title" json:"title"`
	Severity     string   `yaml:"severity" json:"severity"`
	CWE          string   `yaml:"cwe" json:"cwe,omitempty"`
	WhatItIs     string   `yaml:"what" json:"what_it_is"`
	WhyItMatters string   `yaml:"why" json:"why_it_matters"`
	HowToFix     string   `yaml:"fix" json:"how_to_fix"`
	References   []string `yaml:"references" json:"references,omitempty"`
	Safety       string   `yaml:"safety" json:"safety"`
	Tags         []string `yaml:"tags" json:"tags,omitempty"`
}

// SeverityValue parses the rule's severity string.
func (r Rule) SeverityValue() Severity {
	s, _ := ParseSeverity(r.Severity)
	return s
}

// Apply copies the rule's prose and classification into a finding.
func (r Rule) Apply(f *Finding) {
	f.RuleID = r.ID
	f.Engine = r.Engine
	f.Title = r.Title
	f.Severity = r.SeverityValue()
	f.CWE = r.CWE
	f.WhatItIs = r.WhatItIs
	f.WhyItMatters = r.WhyItMatters
	f.HowToFix = r.HowToFix
	f.References = append([]string(nil), r.References...)
}

// NewID returns 16 random bytes as hex.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// SHA256Hex returns the lowercase hex sha256 of s.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Fingerprint identifies a finding stably across scans (Section 3).
func Fingerprint(ruleID, assetKey, location string) string {
	return SHA256Hex(ruleID + "\x00" + assetKey + "\x00" + NormaliseLocation(ruleID, location))
}

// iacSecretRules are the IaC rules whose evidence is a masked credential
// (emitted through the iac emitter's secret path). They fingerprint like
// the secrets engine's rules: by evidence hash, not by line.
var iacSecretRules = map[string]bool{
	"iac.docker.secret-in-env":          true,
	"iac.k8s.secret-in-env":             true,
	"iac.tf.secret-in-variable-default": true,
	"iac.tf.lambda-secret-in-env":       true,
}

// IsSecretRule reports whether findings of ruleID carry a credential as
// evidence. Their location is "file:line#hash" and the fingerprint must not
// move when lines are inserted above, so NormaliseLocation drops the line
// for them. The iac package's tests assert every rule it emits as a secret
// is listed here.
func IsSecretRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "secret.") || iacSecretRules[ruleID]
}

// NormaliseLocation strips volatile parts of a location: line numbers for
// secret findings (which carry the evidence hash instead), query strings for
// URLs, and lowercases hostnames.
func NormaliseLocation(ruleID, loc string) string {
	if IsSecretRule(ruleID) {
		// "file:line#hash" -> "file#hash"; "file:line" -> "file".
		hash := ""
		if i := strings.LastIndex(loc, "#"); i >= 0 {
			hash = loc[i:]
			loc = loc[:i]
		}
		if i := strings.LastIndex(loc, ":"); i >= 0 && isDigits(loc[i+1:]) {
			loc = loc[:i]
		}
		return loc + hash
	}
	if strings.HasPrefix(ruleID, "sca.osv.") {
		// The PURL in the rule ID already identifies the package; the line it
		// sits on in the lockfile is volatile and external tools (trivy,
		// grype) do not report one, so it never takes part in the fingerprint.
		loc = strings.TrimPrefix(strings.TrimPrefix(loc, "./"), "/")
		if i := strings.LastIndex(loc, ":"); i >= 0 && isDigits(loc[i+1:]) {
			loc = loc[:i]
		}
		return strings.ToLower(loc)
	}
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		if u, err := url.Parse(loc); err == nil {
			u.RawQuery = ""
			u.Fragment = ""
			u.Host = strings.ToLower(u.Host)
			return u.String()
		}
	}
	if i := strings.LastIndex(loc, ":"); i > 0 && isDigits(loc[i+1:]) {
		return strings.ToLower(loc[:i]) + loc[i:]
	}
	return strings.ToLower(loc)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// TargetSetHash hashes the sorted asset keys of a target set so scans of
// the same things can be compared.
func TargetSetHash(targets []Target) string {
	keys := make([]string, 0, len(targets))
	for _, t := range targets {
		keys = append(keys, t.AssetKey())
	}
	sort.Strings(keys)
	return SHA256Hex(strings.Join(keys, "\n"))
}
