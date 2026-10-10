// Package sca parses lockfiles and looks installed versions up in OSV.
package sca

import (
	"context"
	"embed"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
)

//go:embed rules/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "sca"

// Engine implements engine.Engine.
type Engine struct {
	rules engine.RuleSet
	// Online is the api.osv.dev client used when the scan is online.
	Online Lookup
	// Offline is the local bundle matcher used with --offline; nil or empty
	// means offline SCA is skipped.
	Offline Lookup
}

// New loads rules; the online client is injected by the caller (it needs
// the store for caching). Set Offline for bundle-backed lookups.
func New(online Lookup) (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	if online == nil {
		online = &OSVClient{}
	}
	return &Engine{rules: rs, Online: online}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Rules exposes the rule prose for adapters that emit shared-scheme SCA
// findings (trivy, grype).
func (e *Engine) Rules() engine.RuleSet { return e.rules }

// Supports path targets.
func (e *Engine) Supports(t domain.Target) bool { return t.Type == domain.TargetPath }

// Collect walks the tree and parses every supported lockfile.
func Collect(ctx context.Context, root string) ([]Package, []string, error) {
	var pkgs []Package
	var files []string
	_, err := engine.WalkFiles(ctx, root, func(rel string, content []byte) error {
		p, ok := ParserFor(path.Base(rel))
		if !ok {
			return nil
		}
		if len(content) > MaxLockfileBytes {
			return nil
		}
		got, err := p.Parse(rel, content)
		if err != nil {
			return nil // a malformed lockfile is skipped, not fatal
		}
		files = append(files, rel)
		pkgs = append(pkgs, got...)
		return nil
	})
	return pkgs, files, err
}

// Plan implements engine.Engine.
func (e *Engine) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	pkgs, files, err := Collect(ctx, t.Value)
	if err != nil {
		return engine.Plan{}, err
	}
	p := engine.Plan{Summary: fmt.Sprintf("%d packages from %d lockfile(s)", len(pkgs), len(files)), Network: o.Online}
	switch {
	case o.Online:
		p.Summary += "; package names and versions will be sent to api.osv.dev"
		p.EstRequests = len(pkgs)/osvBatchSize + 1
		p.EstDuration = 10 * time.Second
	case e.offlineAvailable(ctx):
		p.Summary += "; offline: matched against the local OSV bundle"
		p.EstDuration = 5 * time.Second
	default:
		p.Summary += "; offline: OSV lookup skipped (no bundle loaded)"
	}
	return p, nil
}

// availabler is implemented by offline sources that can be empty.
type availabler interface {
	Available(ctx context.Context) (bool, error)
}

func (e *Engine) offlineAvailable(ctx context.Context) bool {
	if e.Offline == nil {
		return false
	}
	if a, ok := e.Offline.(availabler); ok {
		ok, err := a.Available(ctx)
		return ok && err == nil
	}
	return true
}

// RuleVersionUnparsed is emitted once per lookup when offline matching met
// versions it could not compare.
const RuleVersionUnparsed = "sca.version-unparsed"

// RuleRangeUnevaluated is emitted once per ecosystem per lookup when
// offline matching met advisory ranges it could not evaluate; the engine
// run is then reported partial.
const RuleRangeUnevaluated = "sca.range-unevaluated"

// unevaluatedRef is one (package, advisory) pair the offline matcher could
// not place.
type unevaluatedRef struct {
	Pkg    Package
	VulnID string
	Reason string
}

// offlineGaps collects what one offline lookup could not evaluate.
type offlineGaps struct {
	unparsed    []Package
	unevaluated []unevaluatedRef
}

// SkipReasonOffline is the engine status reason when no bundle is loaded.
const SkipReasonOffline = "offline"

// source picks the vulnerability source for this run. gaps collects what
// the offline matcher could not place; it is per call so the shared client
// stays stateless.
func (e *Engine) source(ctx context.Context, o engine.Options, gaps *offlineGaps) (Lookup, error) {
	if o.Online {
		return e.Online, nil
	}
	if !e.offlineAvailable(ctx) {
		return nil, &engine.SkipError{Reason: SkipReasonOffline}
	}
	if oc, ok := e.Offline.(*OfflineClient); ok {
		return oc.WithReporters(
			func(p Package) { gaps.unparsed = append(gaps.unparsed, p) },
			func(p Package, id, reason string) {
				gaps.unevaluated = append(gaps.unevaluated, unevaluatedRef{Pkg: p, VulnID: id, Reason: reason})
			}), nil
	}
	return e.Offline, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	pkgs, _, err := Collect(ctx, t.Value)
	if err != nil {
		return err
	}
	if len(pkgs) == 0 {
		return nil
	}
	return e.Lookup(ctx, pkgs, t.AssetKey(), Name, o, emit)
}

// MaxLookupPackages caps how many packages one Lookup sends to OSV. A tree
// or image with many lockfiles can exceed any single file's cap; the excess
// is dropped and reported as sca.lookup-truncated, never silently.
const MaxLookupPackages = 200_000

// RuleLookupTruncated is emitted when Lookup dropped packages past the cap.
const RuleLookupTruncated = "sca.lookup-truncated"

// Lookup queries OSV for pkgs and emits one finding per (vulnerability,
// package) under the shared sca.osv.<id>@<purl> scheme. label names the
// engine in the evidence text so a finding reached by several engines
// (native, image, trivy, grype) lists each of them. Offline without a
// bundle yields a SkipError, and offline with advisory ranges the matcher
// could not evaluate yields a PartialError after every finding is emitted,
// so the caller's scan is marked partial, not failed.
func (e *Engine) Lookup(ctx context.Context, pkgs []Package, assetKey, label string, o engine.Options, emit engine.EmitFunc) error {
	if len(pkgs) == 0 {
		return nil
	}
	var gaps offlineGaps
	src, err := e.source(ctx, o, &gaps)
	if err != nil {
		return err
	}
	if len(pkgs) > MaxLookupPackages {
		f := e.rules.NewFinding(RuleLookupTruncated, assetKey, label, domain.Confirmed)
		f.Evidence = []domain.Evidence{{Kind: "file", Location: label, Redacted: fmt.Sprintf("%s: %d packages found; only the first %d were looked up (%d not checked)", label, len(pkgs), MaxLookupPackages, len(pkgs)-MaxLookupPackages), Hash: domain.SHA256Hex(label)}}
		if err := emit(f); err != nil {
			return err
		}
		pkgs = pkgs[:MaxLookupPackages]
	}
	ids, err := src.QueryBatch(ctx, pkgs)
	if err != nil {
		return err
	}
	if len(gaps.unparsed) > 0 {
		if err := emit(e.unparsedFinding(assetKey, label, gaps.unparsed)); err != nil {
			return err
		}
	}
	for _, f := range e.unevaluatedFindings(assetKey, label, gaps.unevaluated) {
		if err := emit(f); err != nil {
			return err
		}
	}
	if err := e.lookupVulns(ctx, src, pkgs, ids, assetKey, label, emit); err != nil {
		return err
	}
	if n := len(gaps.unevaluated); n > 0 {
		return &engine.PartialError{Reason: fmt.Sprintf("%d advisory range(s) not evaluated offline (%s)", n, RuleRangeUnevaluated)}
	}
	return nil
}

// lookupVulns fetches the matched vulnerabilities and emits one finding
// per (vulnerability, package).
func (e *Engine) lookupVulns(ctx context.Context, src Lookup, pkgs []Package, ids [][]string, assetKey, label string, emit engine.EmitFunc) error {
	uniq := map[string]bool{}
	var all []string
	for _, l := range ids {
		for _, id := range l {
			if !uniq[id] {
				uniq[id] = true
				all = append(all, id)
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	vulns, err := src.GetVulns(ctx, all)
	if err != nil {
		return err
	}
	for i, p := range pkgs {
		for _, id := range ids[i] {
			v := vulns[id]
			if v == nil {
				continue
			}
			if err := emit(e.finding(assetKey, label, p, v)); err != nil {
				return err
			}
		}
	}
	return nil
}

// unparsedFinding summarises the packages whose versions the offline
// matcher could not compare (at most ten are named).
func (e *Engine) unparsedFinding(assetKey, label string, pkgs []Package) domain.Finding {
	f := e.rules.NewFinding(RuleVersionUnparsed, assetKey, label, domain.Confirmed)
	names := make([]string, 0, 10)
	for _, p := range pkgs {
		if len(names) == 10 {
			names = append(names, "...")
			break
		}
		names = append(names, p.Name+"@"+p.Version)
	}
	f.Evidence = []domain.Evidence{{Kind: "file", Location: label, Redacted: fmt.Sprintf("%s: %d package version(s) not valid semver, not compared: %s", label, len(pkgs), strings.Join(names, ", ")), Hash: domain.SHA256Hex(label)}}
	return f
}

// unevaluatedFindings summarises, one finding per ecosystem, the
// (package, advisory) pairs the offline matcher could not evaluate (at most
// ten are named per ecosystem). Aggregating keeps a Debian image with
// thousands of ranges-only advisories from flooding the report.
func (e *Engine) unevaluatedFindings(assetKey, label string, refs []unevaluatedRef) []domain.Finding {
	byEco := map[string][]unevaluatedRef{}
	var ecos []string
	for _, r := range refs {
		if _, ok := byEco[r.Pkg.Ecosystem]; !ok {
			ecos = append(ecos, r.Pkg.Ecosystem)
		}
		byEco[r.Pkg.Ecosystem] = append(byEco[r.Pkg.Ecosystem], r)
	}
	sort.Strings(ecos)
	out := make([]domain.Finding, 0, len(ecos))
	for _, eco := range ecos {
		rs := byEco[eco]
		loc := label + " " + eco
		f := e.rules.NewFinding(RuleRangeUnevaluated, assetKey, loc, domain.Confirmed)
		examples := make([]string, 0, 11)
		reasons := map[string]int{}
		for _, r := range rs {
			reasons[r.Reason]++
			if len(examples) == 10 {
				examples = append(examples, "...")
				continue
			}
			examples = append(examples, r.Pkg.Name+"@"+r.Pkg.Version+" ("+r.VulnID+")")
		}
		var why []string
		for _, k := range sortedKeys(reasons) {
			why = append(why, fmt.Sprintf("%d %s", reasons[k], k))
		}
		f.Evidence = []domain.Evidence{{Kind: "file", Location: loc, Redacted: fmt.Sprintf("%s: %d %s advisory range(s) could not be evaluated offline (%s); affected packages may be missing: %s", label, len(rs), eco, strings.Join(why, "; "), strings.Join(examples, ", ")), Hash: domain.SHA256Hex(loc)}}
		out = append(out, f)
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

var cvssV3Re = regexp.MustCompile(`^CVSS:3\.[01]/`)

// VulnRuleID returns the shared rule ID for a vulnerability in a package:
// the CVE alias when one exists (so every tool agrees), else the source ID.
func VulnRuleID(id string, aliases []string, purl string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			id = a
			break
		}
	}
	return "sca.osv." + id + "@" + purl
}

func (e *Engine) finding(assetKey, label string, p Package, v *Vuln) domain.Finding {
	purl := p.PURL()
	loc := p.File
	if p.Line > 0 {
		loc += ":" + strconv.Itoa(p.Line)
	}
	f := domain.Finding{AssetKey: assetKey, Location: loc, Confidence: domain.Firm, Status: domain.StatusOpen}
	e.rules.MustGet("sca.vulnerable-dependency").Apply(&f)
	f.RuleID = VulnRuleID(v.ID, v.Aliases, purl)
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, loc)
	title := v.Summary
	if title == "" {
		title = v.ID
	}
	f.Title = fmt.Sprintf("%s %s: %s", p.Name, p.Version, title)
	f.WhatItIs = fmt.Sprintf("%s version %s (from %s) is affected by %s. %s", p.Name, p.Version, p.File, v.ID, firstSentence(v.Details))
	for _, a := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(a, "CVE-") {
			f.CVEs = append(f.CVEs, a)
		}
	}
	if f.CVEs == nil {
		f.CVEs = []string{}
	}
	if len(v.DatabaseSpecific.CWEIDs) > 0 {
		f.CWE = v.DatabaseSpecific.CWEIDs[0]
	}
	f.References = []string{"https://osv.dev/vulnerability/" + v.ID}
	for _, r := range v.References {
		if r.URL != "" && len(f.References) < 6 {
			f.References = append(f.References, r.URL)
		}
	}
	f.Severity, f.CVSS = severityFor(v)
	if fixed := fixedVersion(v, p); fixed != "" {
		f.HowToFix = fmt.Sprintf("Upgrade `%s` to `%s` or later.", p.Name, fixed)
	} else {
		f.HowToFix = fmt.Sprintf("No fixed version is published yet for `%s`. Check %s for mitigations and watch for a release.", p.Name, f.References[0])
	}
	f.Evidence = []domain.Evidence{PackageEvidence(label, loc, p.Ecosystem, p.Name, p.Version, purl)}
	return f
}

// PackageEvidence is the evidence row every SCA source attaches: which
// engine saw the package, in which ecosystem, at which version. The hash is
// of the PURL so re-scans confirm the same package without storing more.
func PackageEvidence(engineLabel, loc, ecosystem, name, version, purl string) domain.Evidence {
	return domain.Evidence{Kind: "file", Location: loc, Redacted: fmt.Sprintf("%s: %s %s %s", engineLabel, ecosystem, name, version), Hash: domain.SHA256Hex(purl)}
}

func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 && i < 300 {
		return s[:i+1]
	}
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// severityFor derives Severity from CVSS v3 in severity[], else
// database_specific.severity, else Medium.
func severityFor(v *Vuln) (domain.Severity, *domain.CVSS) {
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") && cvssV3Re.MatchString(s.Score) {
			score := cvssV3BaseScore(s.Score)
			if score > 0 {
				return severityFromScore(score), &domain.CVSS{Vector: s.Score, Score: score}
			}
		}
	}
	label := v.DatabaseSpecific.Severity
	if label == "" {
		for _, a := range v.Affected {
			if a.DatabaseSpecific.Severity != "" {
				label = a.DatabaseSpecific.Severity
				break
			}
			if a.EcosystemSpecific.Severity != "" {
				label = a.EcosystemSpecific.Severity
				break
			}
		}
	}
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return domain.Critical, nil
	case "HIGH":
		return domain.High, nil
	case "MODERATE", "MEDIUM":
		return domain.Medium, nil
	case "LOW":
		return domain.Low, nil
	}
	return domain.Medium, nil
}

func severityFromScore(s float64) domain.Severity {
	switch {
	case s >= 9.0:
		return domain.Critical
	case s >= 7.0:
		return domain.High
	case s >= 4.0:
		return domain.Medium
	case s > 0:
		return domain.Low
	}
	return domain.Info
}

// fixedVersion returns the first "fixed" event across ranges for the
// package; it prefers the smallest fixed version greater than installed
// when versions are comparable, else the first listed.
func fixedVersion(v *Vuln, p Package) string {
	var fixes []string
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, p.Ecosystem) || !strings.EqualFold(a.Package.Name, p.QueryName()) {
			continue
		}
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					fixes = append(fixes, ev.Fixed)
				}
			}
		}
	}
	if len(fixes) == 0 {
		return ""
	}
	sort.SliceStable(fixes, func(i, j int) bool { return compareVersions(fixes[i], fixes[j]) < 0 })
	for _, f := range fixes {
		if compareVersions(f, p.Version) > 0 {
			return f
		}
	}
	return fixes[len(fixes)-1]
}

// compareVersions is a lenient dotted-numeric comparison (good enough for
// picking a fix to name; Phase 4 adds semver matching).
func compareVersions(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(leadingDigits(as[i]))
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(leadingDigits(bs[i]))
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

func leadingDigits(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}
