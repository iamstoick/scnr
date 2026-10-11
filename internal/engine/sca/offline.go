package sca

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/iamstoick/scnr/internal/store"
)

// OfflineStore is the store subset the offline matcher reads.
type OfflineStore interface {
	AffectedFor(ctx context.Context, ecosystem, name string) ([]store.AffectedRecord, error)
	AffectedByIDs(ctx context.Context, ids []string) ([]store.AffectedRecord, error)
	OSVAffectedCount(ctx context.Context) (int, error)
}

// OfflineClient implements Lookup against osv_affected rows loaded from a
// signed bundle. It is stateless between calls so one instance is safe for
// the engines that share it (sca and image run concurrently).
type OfflineClient struct {
	Store OfflineStore
	// Unparsed, when set, is called once per package whose version could
	// not be parsed as semver in a semver ecosystem (the package is treated
	// as not affected and the caller reports sca.version-unparsed).
	Unparsed func(Package)
	// Unevaluated, when set, is called for every (package, record) pair the
	// matcher could not place because part of the record's affected set is
	// not evaluable offline (see Match.Unevaluated). The pair is treated as
	// not affected and the caller reports sca.range-unevaluated.
	Unevaluated func(p Package, vulnID, reason string)
}

// WithReporters returns a shallow copy reporting unparsed versions and
// unevaluated ranges to the given functions (per-call state without
// sharing it across concurrent lookups).
func (c *OfflineClient) WithReporters(unparsed func(Package), unevaluated func(Package, string, string)) *OfflineClient {
	cp := *c
	cp.Unparsed = unparsed
	cp.Unevaluated = unevaluated
	return &cp
}

// Available reports whether any offline rows are loaded.
func (c *OfflineClient) Available(ctx context.Context) (bool, error) {
	if c == nil || c.Store == nil {
		return false, nil
	}
	n, err := c.Store.OSVAffectedCount(ctx)
	return n > 0, err
}

// QueryBatch returns, per package, the IDs of records whose version set or
// ranges include the installed version. One indexed SELECT per distinct
// (ecosystem, name).
func (c *OfflineClient) QueryBatch(ctx context.Context, pkgs []Package) ([][]string, error) {
	out := make([][]string, len(pkgs))
	cache := map[string][]Record{}
	for i, p := range pkgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := p.Ecosystem + "\x00" + p.QueryName()
		recs, ok := cache[key]
		if !ok {
			rows, err := c.Store.AffectedFor(ctx, p.Ecosystem, p.QueryName())
			if err != nil {
				return nil, fmt.Errorf("offline osv: %w", err)
			}
			recs, err = decodeRows(rows)
			if err != nil {
				return nil, err
			}
			cache[key] = recs
		}
		for j := range recs {
			m := Affects(p.Version, &recs[j])
			if m.Unparsed {
				if c.Unparsed != nil {
					c.Unparsed(p)
				}
				break // one report per package, and no record can match an unparsable version
			}
			if m.Affected {
				out[i] = append(out[i], recs[j].ID)
				continue
			}
			if m.Unevaluated != "" && c.Unevaluated != nil {
				c.Unevaluated(p, recs[j].ID, m.Unevaluated)
			}
		}
	}
	return out, nil
}

// GetVulns loads the records for ids and merges each vulnerability's
// per-package entries into one Vuln.
func (c *OfflineClient) GetVulns(ctx context.Context, ids []string) (map[string]*Vuln, error) {
	rows, err := c.Store.AffectedByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("offline osv: %w", err)
	}
	recs, err := decodeRows(rows)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*Vuln, len(ids))
	for i := range recs {
		r := &recs[i]
		if v, ok := out[r.ID]; ok {
			v.MergeAffected(r)
		} else {
			out[r.ID] = r.ToVuln()
		}
	}
	return out, nil
}

// decodeRows decodes stored bodies. They were validated at load time, so a
// failure here means the database was altered and is reported, not skipped.
func decodeRows(rows []store.AffectedRecord) ([]Record, error) {
	out := make([]Record, 0, len(rows))
	for _, row := range rows {
		r, err := DecodeRecord(row.Body)
		if err != nil {
			return nil, fmt.Errorf("offline osv: stored record %s/%s/%s: %w", row.Ecosystem, row.Name, row.ID, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// semverEcosystems are the OSV ecosystems whose version strings are semver
// (or canonicalise to it with a "v" prefix). Their SEMVER and ECOSYSTEM
// ranges are both evaluated with x/mod/semver: npm advisories, for
// example, declare semver-shaped ECOSYSTEM ranges. Other ecosystems (PyPI,
// RubyGems, Maven, Debian, Alpine) have no comparator in this version and
// rely on versions[], which OSV populates for them; a record for them that
// carries only ranges is reported as unevaluated, never silently passed.
var semverEcosystems = map[string]bool{"npm": true, "go": true, "crates.io": true, "packagist": true, "hex": true, "pub": true}

// SemverEcosystem reports whether ranges are evaluated for ecosystem.
func SemverEcosystem(ecosystem string) bool { return semverEcosystems[strings.ToLower(ecosystem)] }

// Unevaluated reasons reported through Match.Unevaluated.
const (
	// UnevaluatedNoVersions: the ecosystem is not semver and the record
	// declares ranges but no versions[], so nothing could be compared.
	UnevaluatedNoVersions = "ranges only; no version list to match"
	// UnevaluatedBadBoundary: a range boundary was not valid semver and
	// was dropped, so the interval it bounded is uncertain.
	UnevaluatedBadBoundary = "range boundary not valid semver"
)

// Match is the outcome of Affects for one installed version and record.
type Match struct {
	// Affected: the version is in the record's affected set.
	Affected bool
	// Unparsed: the ecosystem is semver-ranged but the installed version is
	// not valid semver (Affected is false: a version we cannot place is not
	// reported as vulnerable; the caller surfaces sca.version-unparsed).
	Unparsed bool
	// Unevaluated names why part of the record could not be evaluated when
	// Affected is false (one of the Unevaluated* constants); empty when the
	// verdict is complete. The caller surfaces sca.range-unevaluated.
	Unevaluated string
}

// Affects reports whether version is in the record's affected set: an
// exact versions[] match first, then range evaluation for semver
// ecosystems.
func Affects(version string, r *Record) Match {
	for _, v := range r.Versions {
		if v == version {
			return Match{Affected: true}
		}
	}
	hasRange := false
	for _, rg := range r.Ranges {
		if rg.Type != "GIT" {
			hasRange = true
			break
		}
	}
	if !hasRange {
		return Match{}
	}
	if !SemverEcosystem(r.Ecosystem) {
		if len(r.Versions) == 0 {
			return Match{Unevaluated: UnevaluatedNoVersions}
		}
		return Match{}
	}
	cv, ok := CanonSemver(version)
	if !ok {
		return Match{Unparsed: true}
	}
	var m Match
	for _, rg := range r.Ranges {
		if rg.Type != "SEMVER" && rg.Type != "ECOSYSTEM" {
			continue
		}
		hit, dropped := inRange(cv, rg.Events)
		if hit {
			return Match{Affected: true}
		}
		if dropped > 0 {
			m.Unevaluated = UnevaluatedBadBoundary
		}
	}
	return m
}

// boundary is one parsed range event.
type boundary struct {
	kind string // "introduced" | "fixed" | "last_affected"
	v    string // canonical semver; "" for introduced "0" (lowest)
	pos  int    // original index, keeps equal versions in source order
}

// less orders boundaries ascending by version with introduced "0" lowest;
// equal versions keep the source order (OSV lists them sorted already,
// and introduced/fixed at the same version is an empty interval).
func (b boundary) less(o boundary) bool {
	switch {
	case b.v == "" && o.v != "":
		return true
	case b.v != "" && o.v == "":
		return false
	case b.v == o.v:
		return b.pos < o.pos
	}
	return semver.Compare(b.v, o.v) < 0
}

// inRange evaluates one range the way OSV's reference does: boundaries
// that are not valid semver are dropped (counted in dropped), the rest are
// sorted by version (introduced "0" lowest, because a source that lists
// events out of order would otherwise close an interval before opening it
// and hide an affected version), then walked: an introduced boundary at or
// below the version opens an affected interval, a fixed boundary at or
// below it closes the interval, last_affected below it closes it too.
func inRange(cv string, events []Event) (affected bool, dropped int) {
	bs := make([]boundary, 0, len(events))
	for i, ev := range events {
		var b boundary
		switch {
		case ev.Introduced == "0":
			b = boundary{kind: "introduced", pos: i}
		case ev.Introduced != "":
			b = boundary{kind: "introduced", v: ev.Introduced, pos: i}
		case ev.Fixed != "":
			b = boundary{kind: "fixed", v: ev.Fixed, pos: i}
		case ev.LastAffected != "":
			b = boundary{kind: "last_affected", v: ev.LastAffected, pos: i}
		default:
			continue
		}
		if b.v != "" {
			c, ok := CanonSemver(b.v)
			if !ok {
				dropped++
				continue
			}
			b.v = c
		}
		bs = append(bs, b)
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].less(bs[j]) })
	for _, b := range bs {
		switch b.kind {
		case "introduced":
			if b.v == "" || semver.Compare(cv, b.v) >= 0 {
				affected = true
			}
		case "fixed":
			if semver.Compare(cv, b.v) >= 0 {
				affected = false
			}
		case "last_affected":
			if semver.Compare(cv, b.v) > 0 {
				affected = false
			}
		}
	}
	return affected, dropped
}

// CanonSemver returns the x/mod/semver form ("v" prefix) of a version, or
// false when it is not valid semver.
func CanonSemver(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	if v[0] != 'v' && v[0] != 'V' {
		v = "v" + v
	} else {
		v = "v" + v[1:]
	}
	if !semver.IsValid(v) {
		return "", false
	}
	return v, true
}
