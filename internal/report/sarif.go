package report

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/risk"
	"github.com/iamstoick/scnr/internal/store"
)

// SARIF 2.1.0 writer with own structs (no dependency). One run per engine;
// rules are derived from the findings' authored prose.

// SARIFSchemaURI is the published schema location.
const SARIFSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

// SARIFMaxResults bounds the in-memory result set (SARIF has no streaming
// shape with multiple runs); the JSON report always holds everything.
const SARIFMaxResults = 20000

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool         `json:"tool"`
	AutomationDetails *sarifAutomation  `json:"automationDetails,omitempty"`
	Invocations       []sarifInvocation `json:"invocations"`
	Results           []sarifResult     `json:"results"`
	ColumnKind        string            `json:"columnKind"`
	Properties        map[string]any    `json:"properties,omitempty"`
}

type sarifAutomation struct {
	ID string `json:"id"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUtc        string `json:"startTimeUtc,omitempty"`
	EndTimeUtc          string `json:"endTimeUtc,omitempty"`
	ExitCode            *int   `json:"exitCode,omitempty"`
	ExitCodeDescription string `json:"exitCodeDescription,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifMessage   `json:"shortDescription"`
	FullDescription      *sarifMessage  `json:"fullDescription,omitempty"`
	Help                 *sarifMessage  `json:"help,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifConfig   `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Kind                string             `json:"kind,omitempty"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	BaselineState       string             `json:"baselineState,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// SARIF implements Reporter.
type SARIF struct{ Meta Meta }

// Name implements Reporter.
func (s *SARIF) Name() string { return "sarif" }

// FileName implements Reporter.
func (s *SARIF) FileName() string { return "report.sarif" }

// sarifLevel maps a risk bucket to a SARIF level.
func sarifLevel(f domain.Finding) string {
	switch risk.Bucket(f.Risk) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	}
	return "none"
}

func severityLevel(s domain.Severity) string {
	switch s {
	case domain.Critical, domain.High:
		return "error"
	case domain.Medium:
		return "warning"
	case domain.Low:
		return "note"
	}
	return "none"
}

// securitySeverity is the GitHub code-scanning convention (CVSS-like 0-10).
func securitySeverity(f domain.Finding) string {
	if f.CVSS != nil && f.CVSS.Score > 0 {
		return strconv.FormatFloat(f.CVSS.Score, 'f', 1, 64)
	}
	switch f.Severity {
	case domain.Critical:
		return "9.5"
	case domain.High:
		return "8.0"
	case domain.Medium:
		return "5.5"
	case domain.Low:
		return "2.5"
	}
	return "0.5"
}

// sarifLocationFor maps a finding location to SARIF: files get a physical
// location relative to the repository root, URLs a physical location with
// the URL as uri, hosts a logical location.
func sarifLocationFor(f domain.Finding, roots map[string]string) sarifLocation {
	loc := f.Location
	if i := strings.LastIndex(loc, "#"); i > 0 && strings.HasPrefix(f.RuleID, "secret.") {
		loc = loc[:i]
	}
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		if u, err := url.Parse(loc); err == nil && u.User == nil {
			return sarifLocation{PhysicalLocation: &sarifPhysical{ArtifactLocation: sarifArtifact{URI: u.String()}}}
		}
	}
	if strings.HasPrefix(f.AssetKey, "repo:") {
		root := roots[f.AssetKey]
		file, line := splitFileLine(loc)
		if root != "" && strings.HasPrefix(file, root) {
			file = strings.TrimPrefix(strings.TrimPrefix(file, root), "/")
		}
		pl := &sarifPhysical{ArtifactLocation: sarifArtifact{URI: file, URIBaseID: "%SRCROOT%"}}
		if line > 0 {
			pl.Region = &sarifRegion{StartLine: line}
		}
		return sarifLocation{PhysicalLocation: pl}
	}
	return sarifLocation{LogicalLocations: []sarifLogical{{Name: loc, Kind: "address"}}}
}

func splitFileLine(loc string) (string, int) {
	i := strings.LastIndex(loc, ":")
	if i <= 0 {
		return loc, 0
	}
	n, err := strconv.Atoi(loc[i+1:])
	if err != nil {
		return loc, 0
	}
	return loc[:i], n
}

// Write implements Reporter.
func (s *SARIF) Write(ctx context.Context, it *store.FindingIterator, scan domain.Scan, w io.Writer) error {
	roots := map[string]string{}
	for _, t := range scan.Targets {
		if t.Type == domain.TargetPath {
			roots[t.AssetKey()] = t.Value
		}
	}
	type engineAcc struct {
		rules   []sarifRule
		ruleIdx map[string]int
		results []sarifResult
	}
	byEngine := map[string]*engineAcc{}
	var engines []string
	total := 0
	for {
		f, ok := it.Next(ctx)
		if !ok {
			break
		}
		total++
		if total > SARIFMaxResults {
			continue
		}
		acc := byEngine[f.Engine]
		if acc == nil {
			acc = &engineAcc{ruleIdx: map[string]int{}}
			byEngine[f.Engine] = acc
			engines = append(engines, f.Engine)
		}
		idx, seen := acc.ruleIdx[f.RuleID]
		if !seen {
			idx = len(acc.rules)
			acc.ruleIdx[f.RuleID] = idx
			acc.rules = append(acc.rules, ruleFor(f))
		}
		res := sarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           idx,
			Level:               sarifLevel(f),
			Message:             sarifMessage{Text: messageFor(f)},
			Locations:           []sarifLocation{sarifLocationFor(f, roots)},
			PartialFingerprints: map[string]string{"scnr/v1": f.Fingerprint},
			Properties: map[string]any{
				"risk": f.Risk, "severity": f.Severity.String(), "confidence": f.Confidence.String(), "status": string(f.Status),
				"asset": f.AssetKey, "kev": f.KEV, "cves": nonNilStrings(f.CVEs),
			},
		}
		if f.EPSS != nil {
			res.Properties["epss"] = *f.EPSS
		}
		switch f.Status {
		case domain.StatusAccepted:
			res.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: "risk accepted in scnr"}}
		case domain.StatusSuppressed:
			res.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: "suppressed by scnr baseline"}}
		case domain.StatusFixed:
			res.BaselineState = "absent"
		}
		acc.results = append(acc.results, res)
	}
	if err := it.Err(); err != nil {
		return err
	}
	sort.Strings(engines)
	runs := make([]sarifRun, 0, len(engines))
	engineRuns := map[string]domain.EngineRun{}
	for _, er := range scan.Engines {
		engineRuns[er.Name] = er
	}
	for _, name := range engines {
		acc := byEngine[name]
		er := engineRuns[name]
		exit := 0
		if er.Status != "ok" && er.Status != "" {
			exit = 1
		}
		driverName := "scnr"
		if strings.HasPrefix(name, "adapter:") {
			driverName = strings.TrimPrefix(name, "adapter:")
		} else if name != "" {
			driverName = "scnr/" + name
		}
		runs = append(runs, sarifRun{
			Tool:              sarifTool{Driver: sarifDriver{Name: driverName, Version: firstNonEmpty(er.Version, s.Meta.Version), InformationURI: "https://github.com/iamstoick/scnr", Rules: acc.rules}},
			AutomationDetails: &sarifAutomation{ID: "scnr/" + scan.ID + "/" + name},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: exit == 0, ExitCode: &exit, ExitCodeDescription: er.Status,
				StartTimeUtc: scan.StartedAt.UTC().Format(time.RFC3339), EndTimeUtc: scan.FinishedAt.UTC().Format(time.RFC3339),
			}},
			Results:    acc.results,
			ColumnKind: "utf16CodeUnits",
			Properties: map[string]any{"engine": name, "scanId": scan.ID, "profile": scan.Profile, "postureScore": scan.Posture.Score, "grade": scan.Posture.Grade, "partial": scan.Partial, "truncated": total > SARIFMaxResults},
		})
	}
	if len(runs) == 0 {
		// A run with no results is still a valid, useful SARIF file.
		exit := 0
		runs = append(runs, sarifRun{Tool: sarifTool{Driver: sarifDriver{Name: "scnr", Version: s.Meta.Version, Rules: []sarifRule{}}},
			Invocations: []sarifInvocation{{ExecutionSuccessful: true, ExitCode: &exit}}, Results: []sarifResult{}, ColumnKind: "utf16CodeUnits"})
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	enc := json.NewEncoder(bw)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sarifLog{Schema: SARIFSchemaURI, Version: "2.1.0", Runs: runs}); err != nil {
		return err
	}
	return bw.Flush()
}

func ruleFor(f domain.Finding) sarifRule {
	props := map[string]any{"security-severity": securitySeverity(f), "tags": []string{"security", f.Engine}}
	if f.CWE != "" {
		props["cwe"] = f.CWE
	}
	r := sarifRule{
		ID:                   f.RuleID,
		Name:                 ruleName(f.RuleID),
		ShortDescription:     sarifMessage{Text: firstNonEmpty(f.Title, f.RuleID)},
		DefaultConfiguration: &sarifConfig{Level: severityLevel(f.Severity)},
		Properties:           props,
	}
	if f.WhatItIs != "" || f.WhyItMatters != "" {
		r.FullDescription = &sarifMessage{Text: strings.TrimSpace(f.WhatItIs + " " + f.WhyItMatters)}
	}
	if f.HowToFix != "" {
		r.Help = &sarifMessage{Text: f.HowToFix, Markdown: "**How to fix:** " + f.HowToFix}
	}
	if len(f.References) > 0 {
		r.HelpURI = f.References[0]
	}
	return r
}

// ruleName turns "net.exposed-db-port" into "NetExposedDbPort".
func ruleName(id string) string {
	var b strings.Builder
	up := true
	for _, r := range id {
		switch {
		case r == '.' || r == '-' || r == ':' || r == '@' || r == '/':
			up = true
		case up:
			b.WriteString(strings.ToUpper(string(r)))
			up = false
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func messageFor(f domain.Finding) string {
	msg := f.Title
	if f.HowToFix != "" {
		msg += ". " + f.HowToFix
	}
	return fmt.Sprintf("%s (risk %d/100, %s, %s)", msg, f.Risk, f.Severity, f.Confidence)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
