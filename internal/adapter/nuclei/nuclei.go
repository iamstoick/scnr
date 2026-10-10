// Package nuclei drives the nuclei binary with its safe template subset
// (dos/fuzz/intrusive/bruteforce/dast excluded, interactsh disabled, HTTP
// templates only, redirects not followed) and parses JSONL output as
// hostile input.
//
// nuclei does its own DNS and TCP, so the safety.Dialer cannot sit in its
// path. The adapter therefore hands nuclei the address the gate pinned
// (with Host header and SNI set to the name) whenever a hostname resolved
// to exactly one address; a public hostname that cannot be pinned that way
// is skipped rather than scanned through a fresh, unchecked DNS answer.
// Private-only scans run unpinned. See SAFETY.md items 3 and 5.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
)

// Name of the engine.
const Name = "adapter:nuclei"

// MinVersion we have fixtures for.
const MinVersion = "3.0.0"

// ExcludedTags are never run (SAFETY.md). Passed as the value of -et.
const ExcludedTags = "dos,fuzz,intrusive,bruteforce,dast"

const (
	outputFile = "nuclei.jsonl"
	// maxLineSize bounds one JSONL line; longer lines are discarded whole
	// and counted, parsing continues with the next line.
	maxLineSize = 1 << 20
	// maxSavedResponse is passed as -response-size-save so nuclei never
	// writes more than this many response bytes per result into the JSONL.
	maxSavedResponse = 64 << 10
	maxRefs          = 10
)

var (
	templateIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}$`)
	cveRe        = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cweRe        = regexp.MustCompile(`^CWE-\d{1,5}$`)
	// hostnameRe is what we accept as a Host header / SNI value; the detector
	// validated the name already, this is the argv boundary.
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)
)

// Adapter implements adapter.Adapter. Binary, MinVersion, Version and
// Detect come from the embedded Base.
type Adapter struct {
	adapter.Base
}

// New builds the adapter.
func New() *Adapter {
	return &Adapter{Base: adapter.Base{BinaryName: "nuclei", Min: MinVersion, VersionArgs: []string{"-version"}}}
}

// Name implements engine.Engine.
func (a *Adapter) Name() string { return Name }

// Supports URL and host targets.
func (a *Adapter) Supports(t domain.Target) bool {
	return t.Type == domain.TargetURL || t.Type == domain.TargetHost
}

// Plan implements engine.Engine.
func (a *Adapter) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	return a.PlanTool(ctx, a, t, o, "safe templates (no interactsh, -et "+ExcludedTags+")", 5*time.Minute)
}

// Args builds the argument array (Section 5.4). It returns an
// *engine.SkipError when the target is public and cannot be pinned to the
// gate-authorised address (see pinnedTarget).
func (a *Adapter) Args(t domain.Target, o engine.Options) ([]string, error) {
	target, hostName, err := pinnedTarget(t, o)
	if err != nil {
		return nil, err
	}
	if err := adapter.FlagSafeValue(target); err != nil {
		return nil, err
	}
	rps, conc := 10, 16
	if o.Limiter != nil {
		rps, conc = o.Limiter.HTTPRPSPerHost, o.Limiter.PerHostConcurrency
	}
	out := filepath.Join(o.Scratch, outputFile)
	args := []string{
		"-u", target,
		"-jsonl", "-o", out,
		"-silent", "-nc", "-duc",
		"-ni",           // no interactsh: nothing phones an out-of-band server
		"-type", "http", // HTTP templates only: no dns/tcp/ssl/javascript/code/headless protocols
		"-disable-redirects", // nuclei would follow redirects without the scope-checked dialer
		"-response-size-save", strconv.Itoa(maxSavedResponse),
		"-rl", strconv.Itoa(rps),
		"-c", strconv.Itoa(conc),
		"-timeout", "10",
		"-et", ExcludedTags,
		"-severity", "info,low,medium,high,critical",
	}
	if hostName != "" {
		// The URL names the pinned IP; the Host header and SNI carry the
		// hostname so the server still sees the request it would have seen.
		args = append(args, "-H", "Host: "+hostName, "-sni", hostName)
	}
	if o.NucleiTemplatesDir != "" {
		if err := adapter.FlagSafeValue(o.NucleiTemplatesDir); err != nil {
			return nil, err
		}
		args = append(args, "-t", o.NucleiTemplatesDir)
	}
	return args, nil
}

// pinnedTarget returns the value for -u and, when the hostname was replaced
// by its gate-pinned address, the hostname to send as Host header and SNI.
//
//   - IP-literal targets are passed through: there is nothing to rebind.
//   - A hostname pinned to exactly one address is rewritten to that address.
//   - A public hostname pinned to several addresses (or none) is skipped:
//     nuclei cannot be told "this name, only these addresses", and running
//     it on a fresh DNS answer would bypass the rebinding check.
//   - A private-only scan runs unpinned (the gate already established that
//     the name resolves inside private space).
func pinnedTarget(t domain.Target, o engine.Options) (target, hostName string, err error) {
	host := t.Hostname
	var u *url.URL
	if t.Type == domain.TargetURL {
		u, err = url.Parse(t.Value)
		if err != nil || u.User != nil || u.Hostname() == "" {
			return "", "", errors.New("nuclei: invalid target URL")
		}
		if host == "" {
			host = u.Hostname()
		}
	} else if host == "" {
		host = t.Value
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return t.Value, "", nil
	}
	if !hostnameRe.MatchString(host) {
		return "", "", fmt.Errorf("nuclei: invalid hostname %q", host)
	}
	var pinned []netip.Addr
	publicScan := t.Public
	if o.Dialer != nil {
		pinned = o.Dialer.Pinned(host)
		publicScan = publicScan || o.Dialer.PinnedPublic()
	}
	switch {
	case len(pinned) == 1:
		ip := pinned[0]
		if u == nil {
			return ip.String(), host, nil
		}
		pu := *u
		switch {
		case u.Port() != "":
			pu.Host = net.JoinHostPort(ip.String(), u.Port())
		case ip.Is6():
			pu.Host = "[" + ip.String() + "]"
		default:
			pu.Host = ip.String()
		}
		return pu.String(), host, nil
	case publicScan:
		what := "no gate-pinned address"
		if len(pinned) > 1 {
			what = fmt.Sprintf("%d gate-pinned addresses", len(pinned))
		}
		return "", "", &engine.SkipError{Reason: fmt.Sprintf(
			"nuclei resolves %q itself and cannot be held to the authorised address (%s); scan one address directly or pass --skip-engines %s (see `scnr doctor`)",
			host, what, Name)}
	}
	return t.Value, "", nil
}

// Run implements engine.Engine.
func (a *Adapter) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	return a.RunTool(ctx, a, t, o, emit, filepath.Join(o.Scratch, outputFile))
}

// result is the field allowlist for one JSONL line.
type result struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string             `json:"name"`
		Severity       string             `json:"severity"`
		Description    string             `json:"description"`
		Remediation    string             `json:"remediation"`
		Reference      adapter.StringList `json:"reference"`
		Tags           adapter.StringList `json:"tags"`
		Classification struct {
			CVEID       adapter.StringList `json:"cve-id"`
			CWEID       adapter.StringList `json:"cwe-id"`
			CVSSMetrics string             `json:"cvss-metrics"`
			CVSSScore   float64            `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	Type             string             `json:"type"`
	Host             string             `json:"host"`
	MatchedAt        string             `json:"matched-at"`
	MatcherName      string             `json:"matcher-name"`
	ExtractedResults adapter.StringList `json:"extracted-results"`
	Request          string             `json:"request"`
	Response         string             `json:"response"`
}

// Parse reads JSONL. A line over maxLineSize is discarded whole and counted,
// as is a malformed one; parsing continues with the next line, and the
// count is reported as an error after every good line has been emitted
// (never a silent empty result, never a lost later finding).
func (a *Adapter) Parse(r io.Reader, emit func(domain.Finding) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	red := safety.NewRedactor()
	bad := 0
	for {
		line, tooLong, rerr := adapter.ReadLine(br, maxLineSize)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return fmt.Errorf("nuclei output: %w", rerr)
		}
		switch {
		case tooLong:
			bad++
		case len(bytes.TrimSpace(line)) > 0:
			var res result
			if err := json.Unmarshal(line, &res); err != nil || !templateIDRe.MatchString(res.TemplateID) {
				bad++
				break
			}
			f, ok := a.finding(&res, red)
			if !ok {
				bad++
				break
			}
			if err := emit(f); err != nil {
				return err
			}
		}
		if rerr != nil {
			break
		}
	}
	if bad > 0 {
		return fmt.Errorf("nuclei output: %d line(s) were malformed or over %d bytes and were skipped", bad, maxLineSize)
	}
	return nil
}

func (a *Adapter) finding(res *result, red *safety.Redactor) (domain.Finding, bool) {
	loc := safety.StripControl(res.MatchedAt)
	if loc == "" {
		loc = safety.StripControl(res.Host)
	}
	if loc == "" || len(loc) > 2048 {
		return domain.Finding{}, false
	}
	assetKey, ok := assetKeyFor(loc, res.Host)
	if !ok {
		return domain.Finding{}, false
	}
	sev, ok := domain.ParseSeverity(res.Info.Severity)
	if !ok {
		if strings.EqualFold(res.Info.Severity, "unknown") {
			sev = domain.Info
		} else {
			return domain.Finding{}, false
		}
	}
	clean := red.Clean
	f := domain.Finding{
		AssetKey:   assetKey,
		RuleID:     "nuclei:" + res.TemplateID,
		Engine:     Name,
		Title:      clean(res.Info.Name, 200),
		Severity:   sev,
		Confidence: domain.Firm,
		Location:   loc,
		Status:     domain.StatusOpen,
	}
	if f.Title == "" {
		f.Title = "nuclei template " + res.TemplateID + " matched"
	}
	f.WhatItIs = clean(res.Info.Description, 2000)
	if f.WhatItIs == "" {
		f.WhatItIs = "nuclei template " + res.TemplateID + " matched this target (no description from nuclei)."
	} else {
		f.WhatItIs += " (description from nuclei)"
	}
	f.WhyItMatters = "This check comes from the community nuclei template corpus; its severity is nuclei's own assessment. Review the referenced advisory for impact details."
	f.HowToFix = clean(res.Info.Remediation, 2000)
	if f.HowToFix == "" {
		f.HowToFix = "Follow the vendor advisory in the references; if none, review the matched response and disable or restrict the exposed feature."
	}
	for _, ref := range res.Info.Reference {
		ref = strings.TrimSpace(safety.StripControl(ref))
		if (strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://")) && len(ref) < 512 && len(f.References) < maxRefs {
			f.References = append(f.References, ref)
		}
	}
	for _, cve := range res.Info.Classification.CVEID {
		cve = strings.ToUpper(strings.TrimSpace(cve))
		if cveRe.MatchString(cve) {
			f.CVEs = append(f.CVEs, cve)
		}
	}
	for _, cwe := range res.Info.Classification.CWEID {
		cwe = strings.ToUpper(strings.TrimSpace(cwe))
		if cweRe.MatchString(cwe) {
			f.CWE = cwe
			break
		}
	}
	if m := safety.StripControl(res.Info.Classification.CVSSMetrics); strings.HasPrefix(m, "CVSS:") && res.Info.Classification.CVSSScore > 0 && res.Info.Classification.CVSSScore <= 10 {
		f.CVSS = &domain.CVSS{Vector: m, Score: res.Info.Classification.CVSSScore}
	}
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, loc)
	// Request/response are trimmed and redacted; curl-command is dropped by
	// the field allowlist.
	if res.Response != "" {
		f.Evidence = append(f.Evidence, red.TextEvidence("response", loc, trim(res.Response)))
	}
	if res.Request != "" {
		f.Evidence = append(f.Evidence, red.TextEvidence("request", loc, trim(res.Request)))
	}
	for _, x := range res.ExtractedResults {
		if len(f.Evidence) >= domain.MaxEvidencePerFinding {
			break
		}
		f.Evidence = append(f.Evidence, red.TextEvidence("tool_output", loc, "extracted: "+trim(x)))
	}
	if len(f.Evidence) == 0 {
		f.Evidence = []domain.Evidence{red.TextEvidence("tool_output", loc, "matcher: "+safety.StripControl(res.MatcherName))}
	}
	return f, true
}

func trim(s string) string {
	if len(s) > domain.MaxEvidenceBytes {
		return s[:domain.MaxEvidenceBytes]
	}
	return s
}

// assetKeyFor derives the asset key from matched-at (a URL or host:port).
func assetKeyFor(loc, host string) (string, bool) {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		u, err := url.Parse(loc)
		if err != nil || u.User != nil || u.Hostname() == "" {
			return "", false
		}
		return "url:" + u.Scheme + "://" + strings.ToLower(u.Host) + "/", true
	}
	h := safety.StripControl(host)
	if h == "" {
		h = loc
	}
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || strings.ContainsAny(h, " /@") {
		return "", false
	}
	return "host:" + h, true
}

var _ adapter.Adapter = (*Adapter)(nil)
