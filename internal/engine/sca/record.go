package sca

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/store"
)

// Record is one line of an offline bundle's affected/<eco>.jsonl: a
// vulnerability's entry for one package, normalised from the OSV schema
// with the same field allowlist as Vuln. The bundle is hostile input until
// its signature verifies and strict thereafter: DecodeRecord rejects
// unknown fields, over-long values and malformed identifiers rather than
// skipping them.
type Record struct {
	ID         string          `json:"id"`
	Aliases    []string        `json:"aliases,omitempty"`
	Ecosystem  string          `json:"ecosystem"`
	Name       string          `json:"name"`
	Versions   []string        `json:"versions,omitempty"`
	Ranges     []Range         `json:"ranges,omitempty"`
	Summary    string          `json:"summary,omitempty"`
	Severity   []SeverityEntry `json:"severity,omitempty"`
	Refs       []string        `json:"refs,omitempty"`
	CWE        []string        `json:"cwe,omitempty"`
	Modified   string          `json:"modified,omitempty"`
	DBSeverity string          `json:"db_severity,omitempty"`
}

// Range is an OSV affected range (events sorted ascending by the source).
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one range boundary. Exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// SeverityEntry mirrors OSV severity[] (type + CVSS vector or score).
type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Record caps. A real OSV record is far below every one of these; the caps
// bound what a bundle line can make the loader hold or store.
const (
	MaxRecordBytes     = 1 << 20
	maxRecordAliases   = 64
	maxRecordVersions  = 20_000
	maxRecordRanges    = 64
	maxRangeEvents     = 128
	maxRecordRefs      = 10
	maxRecordCWEs      = 20
	maxRecordSeverity  = 8
	maxRecordSummary   = 200
	maxVersionLen      = 128
	maxPackageNameLen  = 512
	maxEcosystemLen    = 64
	maxSeverityTypeLen = 32
	maxSeverityScore   = 256
	maxRefLen          = 1024
	maxModifiedLen     = 64
)

var (
	cweIDRe        = regexp.MustCompile(`^CWE-\d{1,5}$`)
	rangeTypes     = map[string]bool{"SEMVER": true, "ECOSYSTEM": true, "GIT": true}
	errRecordEmpty = errors.New("empty record")
)

// DecodeRecord strictly decodes one bundle line. It is the fuzz target
// FuzzBundleRecord: it must never panic and must reject anything outside
// the documented shape.
func DecodeRecord(line []byte) (Record, error) {
	var r Record
	if len(bytes.TrimSpace(line)) == 0 {
		return r, errRecordEmpty
	}
	if len(line) > MaxRecordBytes {
		return r, fmt.Errorf("record over %d bytes", MaxRecordBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("record: %w", err)
	}
	if dec.More() {
		return r, errors.New("record: trailing data")
	}
	if err := r.validate(); err != nil {
		return r, fmt.Errorf("record %q: %w", safety.StripControl(r.ID), err)
	}
	return r, nil
}

func (r *Record) validate() error {
	if !validVulnID(r.ID) {
		return errors.New("bad id")
	}
	if !printable(r.Ecosystem, 1, maxEcosystemLen) {
		return errors.New("bad ecosystem")
	}
	if !printable(r.Name, 1, maxPackageNameLen) {
		return errors.New("bad name")
	}
	if len(r.Aliases) > maxRecordAliases {
		return errors.New("too many aliases")
	}
	for _, a := range r.Aliases {
		if !validVulnID(a) {
			return fmt.Errorf("bad alias %q", safety.StripControl(a))
		}
	}
	if len(r.Versions) > maxRecordVersions {
		return errors.New("too many versions")
	}
	for _, v := range r.Versions {
		if !printable(v, 1, maxVersionLen) {
			return errors.New("bad version string")
		}
	}
	if len(r.Ranges) > maxRecordRanges {
		return errors.New("too many ranges")
	}
	for _, rg := range r.Ranges {
		if !rangeTypes[rg.Type] {
			return fmt.Errorf("bad range type %q", safety.StripControl(rg.Type))
		}
		if len(rg.Events) > maxRangeEvents {
			return errors.New("too many range events")
		}
		for _, ev := range rg.Events {
			set := 0
			for _, s := range []string{ev.Introduced, ev.Fixed, ev.LastAffected} {
				if s != "" {
					set++
					if !printable(s, 1, maxVersionLen) {
						return errors.New("bad event version")
					}
				}
			}
			if set != 1 {
				return errors.New("event must set exactly one of introduced, fixed, last_affected")
			}
		}
	}
	if len(r.Summary) > 8*maxRecordSummary {
		return errors.New("summary too long")
	}
	if len(r.Severity) > maxRecordSeverity {
		return errors.New("too many severity entries")
	}
	for _, s := range r.Severity {
		if !printable(s.Type, 1, maxSeverityTypeLen) || !printable(s.Score, 1, maxSeverityScore) {
			return errors.New("bad severity entry")
		}
	}
	if len(r.Refs) > maxRecordRefs {
		return errors.New("too many refs")
	}
	for _, ref := range r.Refs {
		if !validRef(ref) {
			return errors.New("bad ref")
		}
	}
	if len(r.CWE) > maxRecordCWEs {
		return errors.New("too many cwe entries")
	}
	for _, c := range r.CWE {
		if !cweIDRe.MatchString(c) {
			return errors.New("bad cwe")
		}
	}
	if len(r.Modified) > maxModifiedLen || r.Modified != safety.StripControl(r.Modified) {
		return errors.New("bad modified")
	}
	if len(r.DBSeverity) > maxSeverityTypeLen || r.DBSeverity != safety.StripControl(r.DBSeverity) {
		return errors.New("bad db_severity")
	}
	return nil
}

// printable reports whether s is within [min,max] bytes and free of control
// characters (newlines included: these are single-line values).
func printable(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

func validRef(s string) bool {
	if !printable(s, 8, maxRefLen) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// Clean applies the redactor and the summary cap. The loader calls it after
// DecodeRecord so stored bodies never carry control characters or secrets
// a hostile bundle smuggled into prose.
func (r *Record) Clean(red *safety.Redactor) {
	if red == nil {
		red = safety.NewRedactor()
	}
	r.Summary = red.Clean(r.Summary, maxRecordSummary)
	for i, ref := range r.Refs {
		r.Refs[i] = red.Clean(ref, maxRefLen)
	}
}

// RecordsFromVuln normalises an OSV record into one Record per distinct
// package in ecosystem (several affected[] entries for the same package
// are merged: ranges concatenated, versions unioned). Entries for other
// ecosystems are dropped. Text fields are capped here so the bundle, not
// the loader, is where size is decided.
func RecordsFromVuln(v *Vuln, ecosystem string) []Record {
	var out []Record
	index := map[string]int{}
	for _, a := range v.Affected {
		if !ecosystemMatches(a.Package.Ecosystem, ecosystem) || a.Package.Name == "" {
			continue
		}
		key := a.Package.Ecosystem + "\x00" + a.Package.Name
		i, ok := index[key]
		if !ok {
			r := Record{ID: v.ID, Aliases: v.Aliases, Ecosystem: a.Package.Ecosystem, Name: a.Package.Name, Modified: v.Modified,
				Summary: truncate(firstLineOf(v.Summary), maxRecordSummary), DBSeverity: v.DatabaseSpecific.Severity}
			if r.Summary == "" {
				r.Summary = truncate(firstLineOf(v.Details), maxRecordSummary)
			}
			for _, s := range v.Severity {
				if len(r.Severity) < maxRecordSeverity {
					r.Severity = append(r.Severity, SeverityEntry{Type: truncate(s.Type, maxSeverityTypeLen), Score: truncate(s.Score, maxSeverityScore)})
				}
			}
			for _, ref := range v.References {
				if len(r.Refs) < maxRecordRefs && validRef(ref.URL) {
					r.Refs = append(r.Refs, ref.URL)
				}
			}
			for _, c := range v.DatabaseSpecific.CWEIDs {
				if len(r.CWE) < maxRecordCWEs && cweIDRe.MatchString(c) {
					r.CWE = append(r.CWE, c)
				}
			}
			if r.DBSeverity == "" {
				r.DBSeverity = a.DatabaseSpecific.Severity
				if r.DBSeverity == "" {
					r.DBSeverity = a.EcosystemSpecific.Severity
				}
			}
			index[key] = len(out)
			i = len(out)
			out = append(out, r)
		}
		r := &out[i]
		for _, rg := range a.Ranges {
			if len(r.Ranges) >= maxRecordRanges {
				break
			}
			nr := Range{Type: rg.Type}
			for _, ev := range rg.Events {
				if len(nr.Events) >= maxRangeEvents {
					break
				}
				nr.Events = append(nr.Events, Event(ev))
			}
			r.Ranges = append(r.Ranges, nr)
		}
		seen := map[string]bool{}
		for _, ver := range r.Versions {
			seen[ver] = true
		}
		for _, ver := range a.Versions {
			if !seen[ver] && len(r.Versions) < maxRecordVersions {
				seen[ver] = true
				r.Versions = append(r.Versions, ver)
			}
		}
	}
	return out
}

// ecosystemMatches accepts the exact ecosystem and its versioned forms
// ("Alpine" matches "Alpine:v3.18"), case-insensitively.
func ecosystemMatches(have, want string) bool {
	return strings.EqualFold(have, want) || strings.HasPrefix(strings.ToLower(have), strings.ToLower(want)+":")
}

// ToVuln expands a Record into the Vuln shape the finding builder reads,
// with a single affected[] entry for the record's package.
func (r *Record) ToVuln() *Vuln {
	v := &Vuln{ID: r.ID, Summary: r.Summary, Details: r.Summary, Aliases: r.Aliases, Modified: r.Modified}
	for _, s := range r.Severity {
		v.Severity = append(v.Severity, struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		}{s.Type, s.Score})
	}
	for _, ref := range r.Refs {
		v.References = append(v.References, struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		}{"WEB", ref})
	}
	v.DatabaseSpecific.CWEIDs = r.CWE
	v.DatabaseSpecific.Severity = r.DBSeverity
	v.Affected = append(v.Affected, affectedFromRecord(r))
	return v
}

// MergeAffected appends r's affected[] entry to v (the same vulnerability
// seen for another package).
func (v *Vuln) MergeAffected(r *Record) {
	v.Affected = append(v.Affected, affectedFromRecord(r))
}

func affectedFromRecord(r *Record) vulnAffected {
	var a vulnAffected
	a.Package.Ecosystem, a.Package.Name = r.Ecosystem, r.Name
	a.Versions = r.Versions
	for _, rg := range r.Ranges {
		var nr vulnRange
		nr.Type = rg.Type
		for _, ev := range rg.Events {
			nr.Events = append(nr.Events, vulnEvent(ev))
		}
		a.Ranges = append(a.Ranges, nr)
	}
	return a
}

// Row converts a validated, cleaned record into its osv_affected row.
func (r *Record) Row() store.AffectedRecord {
	body, _ := json.Marshal(r)
	versions, _ := json.Marshal(r.Versions)
	ranges, _ := json.Marshal(r.Ranges)
	if r.Versions == nil {
		versions = []byte("[]")
	}
	if r.Ranges == nil {
		ranges = []byte("[]")
	}
	return store.AffectedRecord{ID: r.ID, Ecosystem: r.Ecosystem, Name: r.Name, VersionsJSON: string(versions), RangesJSON: string(ranges), Body: body}
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
