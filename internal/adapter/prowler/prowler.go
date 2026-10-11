// Package prowler drives the prowler binary against the AWS account the
// gate confirmed and parses its OCSF JSON output as hostile input. Fixers,
// result uploads (Security Hub, S3), Slack, Shodan and browser auth are
// forbidden flags; prowler talks to the cloud APIs with its own stack, so
// the account binding is: prowler runs after the native identity check,
// with the same profile, and every element whose cloud.account.uid is not
// the confirmed account is dropped and reported. See SAFETY.md item 16.
package prowler

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// Name of the engine.
const Name = "adapter:prowler"

// MinVersion we have fixtures for (OCSF output exists from 3.x; 4.x is the
// first with event_code in metadata).
const MinVersion = "4.0.0"

// Scheme of supported targets.
const Scheme = "aws://"

// Output file prowler writes: -o <scratch> -F <outputStem> → <stem>.ocsf.json.
const (
	outputStem = "prowler"
	outputFile = outputStem + ".ocsf.json"
	maxDesc    = 1000
	maxTitle   = 200
	// maxElements caps the findings read from one report.
	maxElements = 50000
)

// RuleAccountMismatch is emitted when prowler reports resources of an
// account other than the one the scan was authorised for.
const RuleAccountMismatch = "prowler:account-mismatch"

var (
	checkIDRe  = regexp.MustCompile(`^[a-z0-9_]{3,100}$`)
	arnRe      = regexp.MustCompile(`^arn:[a-z-]+:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:.{1,512}$`)
	resourceRe = regexp.MustCompile(`^[A-Za-z0-9:/._@-]{1,512}$`)
	accountRe  = regexp.MustCompile(`^[0-9]{12}$`)
	regionRe   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
)

// passEnv is the environment prowler needs to find the same credentials
// the native engine used. scnr sets none of these itself.
var passEnv = []string{
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION",
	"AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
	"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID",
	"GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG",
}

//go:embed cloud_dedupe.yaml
var dedupeYAML []byte

// Dedupe maps prowler check ids to the native cloud-aws rule ids so both
// engines produce one fingerprint for the same misconfiguration.
func Dedupe() (map[string]string, error) {
	var m map[string]string
	dec := yaml.NewDecoder(strings.NewReader(string(dedupeYAML)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("cloud_dedupe.yaml: %w", err)
	}
	for k, v := range m {
		if !checkIDRe.MatchString(k) || !engine.RuleIDPattern.MatchString(v) || !strings.HasPrefix(v, "cloud.aws.") {
			return nil, fmt.Errorf("cloud_dedupe.yaml: bad entry %q: %q", k, v)
		}
	}
	return m, nil
}

// Adapter implements adapter.Adapter.
type Adapter struct {
	adapter.Base
	// Regions restricts prowler to cloud.aws.regions (-f); empty = all.
	Regions []string
	// Native is the cloud-aws rule set; mapped findings take its prose.
	Native engine.RuleSet
	dedupe map[string]string
}

// New builds the adapter. native may be nil (no dedupe prose; mapped
// findings still carry the native rule id).
func New(regions []string, native engine.RuleSet) (*Adapter, error) {
	d, err := Dedupe()
	if err != nil {
		return nil, err
	}
	return &Adapter{
		Base:    adapter.Base{BinaryName: "prowler", Min: MinVersion, VersionArgs: []string{"--version"}, ExtraEnv: passEnv},
		Regions: regions, Native: native, dedupe: d,
	}, nil
}

// Name implements engine.Engine.
func (a *Adapter) Name() string { return Name }

// Supports aws:// cloud targets (Azure/GCP need a target type that does
// not exist yet; see the package doc).
func (a *Adapter) Supports(t domain.Target) bool {
	return t.Type == domain.TargetCloud && strings.HasPrefix(t.Value, Scheme)
}

// Plan implements engine.Engine.
func (a *Adapter) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	return a.PlanTool(ctx, a, t, o, "AWS checks (OCSF output, no fixers/uploads)", 10*time.Minute)
}

// Args builds the argument array (spec 3.3). The target must be the
// gate-confirmed aws://<account> form; the profile comes from the label
// the gate set, so prowler and the native engine use the same one.
func (a *Adapter) Args(t domain.Target, o engine.Options) ([]string, error) {
	if accountOf(t) == "" {
		return nil, fmt.Errorf("prowler: target %q was not confirmed by the gate", t.Value)
	}
	if err := adapter.FlagSafePath(o.Scratch); err != nil {
		return nil, err
	}
	args := []string{
		"aws",
		"-M", "json-ocsf", // single machine-readable format
		"-o", o.Scratch, "-F", outputStem, // fixed output location and name
		"-z",         // exit 0 even when findings exist
		"-b",         // no banner
		"--no-color", // plain output for the stderr tail
	}
	if p := t.Labels["profile"]; p != "" {
		if err := adapter.FlagSafeValue(p); err != nil {
			return nil, err
		}
		args = append(args, "-p", p)
	}
	if len(a.Regions) > 0 {
		args = append(args, "-f")
		for _, r := range a.Regions {
			if !regionRe.MatchString(r) {
				return nil, fmt.Errorf("prowler: bad region %q", r)
			}
			args = append(args, r)
		}
	}
	return args, nil
}

func accountOf(t domain.Target) string {
	rest := strings.TrimPrefix(t.Value, Scheme)
	if accountRe.MatchString(rest) {
		return rest
	}
	return ""
}

// Run implements engine.Engine. Findings whose account is not the
// authorised one are dropped here (Parse has no target) and reported
// once as prowler:account-mismatch.
func (a *Adapter) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	account := accountOf(t)
	assetKey := "aws:" + account
	other := map[string]int{}
	filtered := func(f domain.Finding) error {
		if f.AssetKey != assetKey {
			other[strings.TrimPrefix(f.AssetKey, "aws:")]++
			return nil
		}
		return emit(f)
	}
	err := a.RunTool(ctx, a, t, o, filtered, filepath.Join(o.Scratch, outputFile))
	for acct, n := range other {
		f := domain.Finding{
			AssetKey: assetKey, RuleID: RuleAccountMismatch, Engine: Name, Severity: domain.High, Confidence: domain.Confirmed,
			Location: "prowler:account/" + acct, Status: domain.StatusOpen,
			Title:        "prowler reported findings for a different AWS account",
			WhatItIs:     fmt.Sprintf("%d prowler finding(s) referred to account %s, but this scan was authorised for account %s. They were dropped.", n, acct, account),
			WhyItMatters: "prowler resolves credentials on its own; a profile or environment pointing at another account means the two engines did not examine the same account, and results for the other account were never authorised.",
			HowToFix:     "Make AWS_PROFILE / the aws://<profile> target and prowler's -p agree, and confirm cloud.aws.accounts lists the account you intend to scan.",
		}
		f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, f.Location)
		if eerr := emit(f); eerr != nil {
			return eerr
		}
	}
	return err
}

// element is the OCSF field allowlist.
type element struct {
	Metadata struct {
		EventCode string `json:"event_code"`
	} `json:"metadata"`
	FindingInfo struct {
		UID   string `json:"uid"`
		Title string `json:"title"`
	} `json:"finding_info"`
	SeverityID int    `json:"severity_id"`
	StatusCode string `json:"status_code"`
	Resources  []struct {
		UID    string `json:"uid"`
		Type   string `json:"type"`
		Name   string `json:"name"`
		Region string `json:"region"`
	} `json:"resources"`
	Remediation struct {
		Desc       string             `json:"desc"`
		References adapter.StringList `json:"references"`
	} `json:"remediation"`
	Cloud struct {
		Account struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
}

// Parse streams the top-level OCSF array. PASS/MANUAL elements are skipped
// silently (they are coverage, not findings); malformed ones are counted
// and reported after every good finding was emitted; the element cap
// yields a PartialError so truncated coverage never marks findings fixed.
func (a *Adapter) Parse(r io.Reader, emit func(domain.Finding) error) error {
	red := safety.NewRedactor()
	n := 0
	truncated := false
	bad, err := adapter.StreamTopLevelArray(r, func(dec *json.Decoder) error {
		var el element
		if err := adapter.DecodeElement(dec, &el); err != nil {
			return err
		}
		if n >= maxElements {
			truncated = true
			return nil
		}
		n++
		if el.StatusCode != "FAIL" {
			return nil
		}
		f, ok := a.finding(&el, red)
		if !ok {
			return adapter.ErrSkipElement
		}
		return emit(f)
	})
	if err != nil {
		return fmt.Errorf("prowler output: %w", err)
	}
	if truncated {
		return &engine.PartialError{Reason: fmt.Sprintf("prowler output had more than %d elements; the rest were not read", maxElements)}
	}
	return adapter.BadCount("prowler", bad)
}

// checkID extracts the check id from metadata.event_code, else from the
// finding uid "prowler-aws-<check>-<account>-<region>-<resource>".
func checkID(el *element) string {
	if id := el.Metadata.EventCode; checkIDRe.MatchString(id) {
		return id
	}
	parts := strings.SplitN(el.FindingInfo.UID, "-", 4)
	if len(parts) < 4 || parts[0] != "prowler" {
		return ""
	}
	// The check id itself contains underscores only; it ends at the first
	// "-<12 digits>".
	rest := parts[2] + "-" + parts[3]
	if i := strings.Index(rest, "-"); i > 0 && checkIDRe.MatchString(rest[:i]) {
		return rest[:i]
	}
	return ""
}

func severity(id int) (domain.Severity, bool) {
	switch id {
	case 0, 1:
		return domain.Info, true
	case 2:
		return domain.Low, true
	case 3:
		return domain.Medium, true
	case 4:
		return domain.High, true
	case 5, 6:
		return domain.Critical, true
	}
	return domain.Info, false
}

func (a *Adapter) finding(el *element, red *safety.Redactor) (domain.Finding, bool) {
	id := checkID(el)
	account := el.Cloud.Account.UID
	if id == "" || !accountRe.MatchString(account) || len(el.Resources) == 0 {
		return domain.Finding{}, false
	}
	sev, ok := severity(el.SeverityID)
	if !ok {
		return domain.Finding{}, false
	}
	res := el.Resources[0]
	loc := safety.StripControl(res.UID)
	if !arnRe.MatchString(loc) {
		typ, name := safety.StripControl(res.Type), safety.StripControl(res.Name)
		loc = "aws:" + typ + "/" + name
		if typ == "" || name == "" || !resourceRe.MatchString(loc) {
			return domain.Finding{}, false
		}
	}
	assetKey := "aws:" + account
	f := domain.Finding{AssetKey: assetKey, Engine: Name, Severity: sev, Confidence: domain.Firm, Location: loc, Status: domain.StatusOpen}
	if native, ok := a.dedupe[id]; ok {
		if a.Native != nil {
			if rule, ok := a.Native[native]; ok {
				rule.Apply(&f)
				f.Engine = Name
			}
		}
		f.RuleID = native
		f.Severity = sev
	} else {
		f.RuleID = "prowler:" + id
	}
	title := red.Clean(el.FindingInfo.Title, maxTitle)
	if title == "" {
		title = "prowler check " + id + " failed"
	}
	if f.Title == "" {
		f.Title = title
	}
	if f.WhatItIs == "" {
		f.WhatItIs = fmt.Sprintf("prowler check %s reported FAIL for this resource: %s (title from prowler)", id, title)
	}
	if f.WhyItMatters == "" {
		f.WhyItMatters = "This check comes from the prowler check library; its severity is prowler's own assessment."
	}
	if fix := red.Clean(el.Remediation.Desc, maxDesc); fix != "" {
		f.HowToFix = fix + " (remediation from prowler)"
	} else if f.HowToFix == "" {
		f.HowToFix = "Follow the references, or prowler's own documentation for check " + id + "."
	}
	if refs := adapter.URLRefs(el.Remediation.References...); len(refs) > 0 {
		f.References = refs
	}
	f.Fingerprint = domain.Fingerprint(f.RuleID, assetKey, loc)
	summary := "check=" + id + " status=FAIL"
	if region := safety.StripControl(res.Region); regionRe.MatchString(region) {
		summary += " region=" + region
	}
	f.Evidence = []domain.Evidence{red.TextEvidence("tool_output", loc, summary)}
	return f, true
}

var _ adapter.Adapter = (*Adapter)(nil)
