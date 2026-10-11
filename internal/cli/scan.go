package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/adapter/grype"
	"github.com/gerald/scnr/internal/adapter/nmap"
	"github.com/gerald/scnr/internal/adapter/nuclei"
	"github.com/gerald/scnr/internal/adapter/prowler"
	"github.com/gerald/scnr/internal/adapter/semgrep"
	"github.com/gerald/scnr/internal/adapter/trivy"
	"github.com/gerald/scnr/internal/audit"
	"github.com/gerald/scnr/internal/config"
	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	cloudaws "github.com/gerald/scnr/internal/engine/cloud/aws"
	"github.com/gerald/scnr/internal/engine/codecheck"
	"github.com/gerald/scnr/internal/engine/iac"
	"github.com/gerald/scnr/internal/engine/image"
	"github.com/gerald/scnr/internal/engine/netscan"
	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/engine/secrets"
	"github.com/gerald/scnr/internal/engine/webscan"
	"github.com/gerald/scnr/internal/report"
	"github.com/gerald/scnr/internal/risk"
	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/store"
	"github.com/gerald/scnr/internal/target"
	"github.com/gerald/scnr/internal/vulndb"
	"github.com/gerald/scnr/internal/wizard"
)

func (a *App) scanCmd() *cobra.Command {
	req := wizard.ScanRequest{}
	var engines, skip string
	cmd := &cobra.Command{
		Use:     "scan [TARGET...]",
		Short:   "Scan one or more targets you are authorised to test",
		Example: "  scnr scan https://app.example.com\n  scnr scan . --format json --out out/ --non-interactive --ack-authorized\n  scnr scan 10.0.0.0/24 --profile quick --ack-authorized --non-interactive",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return a.runWizard(cmd.Context())
			}
			req.Targets = args
			req.Engines = splitList(engines)
			req.SkipEngines = splitList(skip)
			if err := a.Open(cmd.Context()); err != nil {
				return err
			}
			_, code, err := a.RunScan(cmd.Context(), req)
			if err != nil {
				return &ExitError{Code: code, Err: err}
			}
			if code != ExitOK {
				return &ExitError{Code: code}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&req.Profile, "profile", "standard", "quick|standard|deep")
	f.StringVar(&req.Type, "type", "", "override target detection: url|host|cidr|path|image|cloud (a directory is read as an OCI image layout only with --type image)")
	f.StringVar(&engines, "engines", "", "only run these engines (comma list)")
	f.StringVar(&skip, "skip-engines", "", "skip these engines (comma list)")
	f.StringVar(&req.Out, "out", "./scnr-out", "output directory (reports go in <out>/<scan-id>/)")
	f.StringVar(&req.Formats, "format", "html,json", "report formats (comma list)")
	f.BoolVar(&req.NonInteractive, "non-interactive", false, "never prompt; refuse anything needing consent")
	f.BoolVar(&req.Offline, "offline", false, "do not contact osv.dev; SCA uses the loaded offline bundle (scnr db update --offline-bundle) or is skipped")
	f.IntVar(&req.MaxHosts, "max-hosts", 0, "raise the CIDR host cap to N (audited)")
	f.StringVar(&req.Ports, "ports", "", "top100|top1000|all|LIST (e.g. 22,80,8000-8100)")
	f.IntVar(&req.Rate, "rate", 0, "connection attempts per second (lowering is always allowed)")
	f.IntVar(&req.Concurrency, "concurrency", 0, "per-host concurrency")
	f.BoolVar(&req.Strict, "strict", false, "exit 5 when any engine is skipped or fails")
	f.BoolVar(&req.AckAuthorized, "ack-authorized", false, "acknowledge: "+ackShort)
	f.BoolVar(&req.AllowRaise, "i-understand-rate-limits", false, "allow rate/concurrency above 2x default (audited)")
	f.StringVar(&req.Policy, "policy", "", "policy.yaml to evaluate; violations exit 1")
	f.StringVar(&req.Baseline, "baseline", "", "baseline.yaml whose findings are reported as suppressed")
	f.StringVar(&req.Diff, "diff", "", "print new/fixed findings vs a previous scan: latest|SCAN-ID")
	f.StringVar(&req.Templates, "templates", "", "directory of extra webscan templates (validated, safe only)")
	cmd.AddCommand(a.scanListCmds()...)
	return cmd
}

// engines bundles the registry with the engines RunScan wires elsewhere.
type engines struct {
	reg *engine.Registry
	ns  *netscan.Engine
	aws *cloudaws.Engine
}

// engineRegistry builds the native engines plus the adapters.
func (a *App) engineRegistry() (*engines, error) {
	reg := engine.NewRegistry()
	ns, err := netscan.New()
	if err != nil {
		return nil, err
	}
	sec, err := secrets.New()
	if err != nil {
		return nil, err
	}
	osvBase := a.OSVBase
	if osvBase == "" {
		osvBase = sca.DefaultOSVBase
	}
	osvHTTP, err := a.endpointClient(osvBase)
	if err != nil {
		return nil, err
	}
	osvHTTP.Timeout = 60 * time.Second
	osv := &sca.OSVClient{Base: a.OSVBase, Cache: a.Store, HTTP: osvHTTP}
	sc, err := sca.New(osv)
	if err != nil {
		return nil, err
	}
	if a.Store != nil {
		sc.Offline = &sca.OfflineClient{Store: a.Store}
	}
	ws, err := webscan.New()
	if err != nil {
		return nil, err
	}
	img, err := image.New(sc)
	if err != nil {
		return nil, err
	}
	ia, err := iac.New()
	if err != nil {
		return nil, err
	}
	cc, err := codecheck.New()
	if err != nil {
		return nil, err
	}
	aws, err := a.awsEngine()
	if err != nil {
		return nil, err
	}
	adapters, err := a.adapters()
	if err != nil {
		return nil, err
	}
	for _, e := range []engine.Engine{ns, sec, sc, ws, img, ia, cc, aws} {
		reg.Register(e)
	}
	for _, ad := range adapters {
		reg.Register(ad)
	}
	return &engines{reg: reg, ns: ns, aws: aws}, nil
}

// cloudConfig is cloud.aws from the scope file (empty before Open).
func (a *App) cloudConfig() config.CloudAWS {
	if a.Config == nil {
		return config.CloudAWS{}
	}
	return a.Config.Cloud.AWS
}

// awsEngine builds the native AWS posture engine. The endpoint override
// exists for tests only; it is never read from a flag or the config.
func (a *App) awsEngine() (*cloudaws.Engine, error) {
	e, err := cloudaws.New(a.cloudConfig())
	if err != nil {
		return nil, err
	}
	if a.AWSEndpoint != "" {
		host := safety.URLHost(a.AWSEndpoint)
		if host == "" {
			return nil, fmt.Errorf("AWSEndpoint %q: not a URL", a.AWSEndpoint)
		}
		e.BaseEndpoint, e.EndpointHosts = a.AWSEndpoint, []string{host}
	}
	return e, nil
}

// adapters lists the external-tool adapters (doctor reports them too).
func (a *App) adapters() ([]adapter.Adapter, error) {
	nm, err := nmap.New()
	if err != nil {
		return nil, err
	}
	tv, err := trivy.New()
	if err != nil {
		return nil, err
	}
	gr, err := grype.New()
	if err != nil {
		return nil, err
	}
	aws, err := cloudaws.New(a.cloudConfig())
	if err != nil {
		return nil, err
	}
	pw, err := prowler.New(a.cloudConfig().Regions, aws.Rules())
	if err != nil {
		return nil, err
	}
	return []adapter.Adapter{nm, nuclei.New(), semgrep.New(), tv, gr, pw}, nil
}

const ackShort = "I am authorised to scan these targets and accept responsibility for doing so"

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Detector returns the target detector with the app's resolver.
func (a *App) Detector() *target.Detector { return &target.Detector{Resolver: a.Resolver} }

// RunScan executes a scan request end to end and returns the scan, the exit
// code and an error (for refusals/usage). The scan is nil on refusal.
func (a *App) RunScan(ctx context.Context, req wizard.ScanRequest) (*domain.Scan, int, error) {
	if a.configErr != nil {
		return nil, ExitUsage, fmt.Errorf("scope file: %w", a.configErr)
	}
	cfg := a.Config
	profile, err := engine.ProfileByName(req.Profile)
	if err != nil {
		return nil, ExitUsage, err
	}
	typ, err := target.ParseType(req.Type)
	if err != nil {
		return nil, ExitUsage, err
	}
	engs, err := a.engineRegistry()
	if err != nil {
		return nil, ExitUsage, err
	}
	reg := engs.reg
	ports, err := engs.ns.ParsePorts(req.Ports)
	if err != nil {
		return nil, ExitUsage, err
	}
	if _, err := report.ParseFormats(req.Formats, report.Registry(report.Meta{})); err != nil {
		return nil, ExitUsage, err
	}
	// Policy and baseline files are validated before anything runs so a typo
	// fails fast instead of after a long scan.
	var policy *config.Policy
	if req.Policy != "" {
		if policy, err = config.LoadPolicy(req.Policy); err != nil {
			return nil, ExitUsage, fmt.Errorf("--policy: %w", err)
		}
	}
	var baseline *config.Baseline
	if req.Baseline != "" {
		if baseline, err = config.LoadBaseline(req.Baseline); err != nil {
			return nil, ExitUsage, fmt.Errorf("--baseline: %w", err)
		}
	}
	if req.Templates != "" {
		if _, errs := webscan.LoadDir(req.Templates); len(errs) > 0 {
			return nil, ExitUsage, fmt.Errorf("--templates: %w", errors.Join(errs...))
		}
	}
	// The exact template set (embedded merged with --templates) is recorded
	// on the scan audit row so a report can be traced to the checks that ran.
	var templateCount int
	var templateHash string
	if ws, ok := reg.Get(webscan.Name); ok {
		if templateCount, templateHash, err = ws.(*webscan.Engine).TemplateSetInfo(req.Templates); err != nil {
			return nil, ExitUsage, err
		}
	}

	// Targets. Raw inputs are redacted before they reach the store, audit
	// trail, reports or stderr (defence in depth: URL credentials are
	// already rejected by the detector).
	det := a.Detector()
	var targets []domain.Target
	for _, raw := range req.Targets {
		t, err := det.Detect(ctx, raw, typ)
		if err != nil {
			return nil, ExitUsage, a.redactErr(err)
		}
		t.Raw = a.redact(t.Raw)
		targets = append(targets, t)
	}
	rawTargets := make([]string, len(req.Targets))
	for i, r := range req.Targets {
		rawTargets[i] = a.redact(r)
	}
	secretKey, err := safety.LoadOrCreateSecret(a.Home)
	if err != nil {
		return nil, ExitUsage, err
	}

	// Scope, limits, gate.
	scope, err := safety.NewScope(cfg.Scope.Allow, cfg.Scope.Deny)
	if err != nil {
		return nil, ExitUsage, err
	}
	anyPublic := false
	for _, t := range targets {
		if t.Public && t.Type != domain.TargetPath {
			anyPublic = true
		}
	}
	limits, raised, err := safety.NewLimits(anyPublic, safety.LimitRequest{
		RatePerSec: firstNonZero(req.Rate, cfg.Limits.RatePerSec), PerHostConcurrency: firstNonZero(req.Concurrency, cfg.Limits.PerHostConcurrency),
		HTTPRPSPerHost: cfg.Limits.HTTPRPSPerHost, MaxHosts: firstNonZero(req.MaxHosts, cfg.Limits.MaxHosts), AllowRaise: req.AllowRaise,
	})
	if err != nil {
		return nil, ExitRefused, err
	}
	interactive := !req.NonInteractive && a.IsTTY
	acknowledged := cfg.Authorization.Acknowledged || req.AckAuthorized
	if !acknowledged && interactive {
		// Direct `scan TARGET` on a terminal asks the same question the
		// wizard does; the acceptance covers this run only.
		acknowledged = a.ackPrompt()
	}
	verifier := &safety.Verifier{Store: a.Store}
	gate := &safety.Gate{
		Scope: scope, Acknowledged: acknowledged,
		Resolver: a.Resolver, Verified: verifier.IsVerified, MaxHosts: req.MaxHosts,
		CloudIdentity: engs.aws.Identity, CloudAccounts: cfg.Cloud.AWS.Accounts,
	}
	if interactive {
		gate.Consent = a.consentPrompt
	}
	dialer := &safety.Dialer{Scope: scope, Resolver: a.Resolver, Limits: limits}
	httpClient := safety.NewHTTPClient(dialer, safety.HTTPOptions{UserAgent: "scnr/" + a.Version})
	online := !req.Offline
	if cfg.Online != nil && !*cfg.Online {
		online = false
	}
	opts := engine.Options{Profile: profile, Limiter: limits, HTTP: httpClient, Scope: scope, Dialer: dialer, Log: a.Log, Online: online, Ports: ports, Redactor: a.Redactor, SecretKey: secretKey, TemplatesDir: req.Templates, NucleiTemplatesDir: cfg.Tools.NucleiTemplates, SemgrepRules: cfg.Tools.SemgrepRules}

	type planned struct {
		t       domain.Target
		engines []engine.Engine
		dec     *safety.Decision
	}
	var plans []planned
	consentMethod := domain.ConsentLocal
	var cloudIdentity *safety.CloudIdentity
	for i, t := range targets {
		selected, err := reg.Select(t, profile, req.Engines, req.SkipEngines)
		if err != nil {
			return nil, ExitUsage, err
		}
		planText := a.planSummary(ctx, selected, t, opts)
		dec, err := gate.Decide(ctx, t, planText)
		if err != nil {
			err = a.redactErr(err)
			_ = a.Audit.Log(ctx, audit.ActionGateRefused, "", map[string]any{"target": t.Raw, "type": t.Type, "error": err.Error(), "scope_hash": scope.Hash()})
			if safety.IsRefusal(err) {
				return nil, ExitRefused, err
			}
			return nil, ExitUsage, err
		}
		if dec.MaxHostsOverride {
			_ = a.Audit.Log(ctx, audit.ActionLimitOverride, "", map[string]any{"target": t.Raw, "max_hosts": req.MaxHosts, "hosts": dec.HostCount})
		}
		consentMethod = strongerConsent(consentMethod, dec.ConsentMethod)
		if t.Hostname != "" && len(dec.Addrs) > 0 {
			dialer.Pin(t.Hostname, dec.Addrs)
		}
		if dec.Identity != nil {
			// The gate pinned the account: the scan record, asset and every
			// engine see aws://<account>, never the profile form.
			t = dec.Target
			targets[i] = t
			cloudIdentity = dec.Identity
			if dec.Identity.Source == cloudaws.SourceInstance {
				_ = a.Audit.Log(ctx, audit.ActionLimitOverride, "", map[string]any{"target": t.Raw, "instance_credentials": true})
			}
		}
		plans = append(plans, planned{t: t, engines: selected, dec: dec})
	}
	if raised {
		_ = a.Audit.Log(ctx, audit.ActionLimitOverride, "", map[string]any{"rate": limits.RatePerSec, "concurrency": limits.PerHostConcurrency})
	}

	// Scan record.
	scan := &domain.Scan{
		ID: domain.NewID(), StartedAt: time.Now(), Profile: profile.Name, Targets: targets,
		TargetSetHash: domain.TargetSetHash(targets), ScopeHash: scope.Hash(),
		Consent: domain.ConsentRecord{Method: consentMethod, By: audit.Actor(), At: time.Now()},
	}
	if err := a.Store.InsertScan(ctx, scan); err != nil {
		return nil, ExitUsage, err
	}
	for _, t := range targets {
		if _, err := a.Store.UpsertAsset(ctx, domain.Asset{Key: t.AssetKey(), Type: t.Type, Name: t.Value, Public: t.Public, Labels: t.Labels}); err != nil {
			return nil, ExitUsage, err
		}
	}

	scratch, err := os.MkdirTemp("", "scnr-")
	if err != nil {
		return nil, ExitUsage, err
	}
	defer os.RemoveAll(scratch) //nolint:errcheck // best-effort temp cleanup
	opts.Scratch = scratch

	enricher, err := vulndb.NewEnricher(ctx, a.Store)
	if err != nil {
		return nil, ExitUsage, err
	}
	publicKeys := map[string]bool{}
	for _, t := range targets {
		publicKeys[t.AssetKey()] = t.Public
	}
	writer := a.Store.NewWriter(ctx, scan.ID, func(key string) bool {
		if p, ok := publicKeys[key]; ok {
			return p
		}
		return anyPublic
	})
	runner := &engine.Runner{Progress: a.progress}
	engineRuns := map[string]domain.EngineRun{}
	for _, p := range plans {
		exp := risk.ExposureFor(p.t.Type, p.dec.Public)
		emit := func(f domain.Finding) error {
			f.ScanID = scan.ID
			if f.Status == "" {
				f.Status = domain.StatusOpen
			}
			if err := enricher.Enrich(ctx, &f); err != nil {
				return err
			}
			f.Risk = risk.Score(f, exp)
			return writer.Add(f)
		}
		runs, err := runner.Run(ctx, p.engines, p.t, opts, emit)
		for _, r := range runs {
			engineRuns[r.Name] = mergeRun(engineRuns[r.Name], r)
		}
		if err != nil {
			break
		}
	}
	if err := writer.Close(); err != nil {
		return nil, ExitUsage, fmt.Errorf("writing findings: %w", err)
	}
	for _, name := range reg.Names() {
		if r, ok := engineRuns[name]; ok {
			scan.Engines = append(scan.Engines, r)
		}
	}
	partial, allFailed := engine.Summarise(scan.Engines)
	scan.Partial = partial

	// Status lifecycle: baseline, accept-risk (with expiry), fixed. Posture
	// and policy are then computed from the stored statuses.
	life, err := a.applyLifecycle(ctx, scan, baseline, req.Baseline)
	if err != nil {
		return scan, ExitUsage, err
	}
	counts, err := a.scanCounts(ctx, scan.ID)
	if err != nil {
		return scan, ExitUsage, err
	}
	scan.Posture = risk.Posture(counts, partial)
	scan.FinishedAt = time.Now()
	var violations []string
	if policy != nil {
		violations = policy.Evaluate(policyInput(counts, scan))
	}
	switch {
	case allFailed:
		scan.ExitCode = ExitAllFailed
	case len(violations) > 0:
		scan.ExitCode = ExitPolicy
	case partial && req.Strict:
		scan.ExitCode = ExitPartial
	default:
		scan.ExitCode = ExitOK
	}
	if ctx.Err() != nil {
		scan.ExitCode = ExitUsage
	}
	if err := a.Store.FinishScan(ctx, scan); err != nil {
		return scan, ExitUsage, err
	}
	detail := map[string]any{
		"targets": rawTargets, "profile": profile.Name, "scope_hash": scope.Hash(), "consent_method": consentMethod,
		"engines": scan.Engines, "exit_code": scan.ExitCode, "findings": writer.Count(), "score": scan.Posture.Score, "grade": scan.Posture.Grade, "partial": partial,
		"fixed": life.fixed, "accepted": life.accepted, "suppressed": life.suppressed,
		"templates_dir": req.Templates, "templates": templateCount, "templates_hash": templateHash,
	}
	if policy != nil {
		detail["policy"] = map[string]any{"path": policy.Path, "violations": violations}
	}
	if cloudIdentity != nil {
		// Source and principal only: never a key id or token.
		detail["cloud_identity"] = map[string]any{"provider": cloudIdentity.Provider, "account": cloudIdentity.Account, "principal": cloudIdentity.Principal, "source": cloudIdentity.Source}
	}
	_ = a.Audit.Log(context.WithoutCancel(ctx), audit.ActionScan, scan.ID, detail)

	// Reports.
	outDir := filepath.Join(req.Out, scan.ID)
	prev, hasPrev, _ := a.Store.PreviousScanScore(ctx, scan.TargetSetHash, scan.ID)
	meta := report.Meta{ExploitData: enricher.Available, Version: a.Version}
	if hasPrev {
		meta.PreviousScore = &prev
	}
	reporters, _ := report.ParseFormats(req.Formats, report.Registry(meta))
	paths, err := report.WriteAll(ctx, a.Store, *scan, reporters, outDir)
	if err != nil {
		return scan, ExitUsage, err
	}
	a.printSummary(ctx, scan, writer.Count(), paths)
	if life.fixed > 0 || life.accepted > 0 || life.suppressed > 0 || len(life.reverted) > 0 {
		fmt.Fprintf(a.Stdout, "Lifecycle: %d fixed since last scan, %d accepted, %d suppressed by baseline, %d acceptance(s) expired\n", life.fixed, life.accepted, life.suppressed, len(life.reverted))
	}
	if req.Diff != "" {
		other := req.Diff
		if other == "latest" {
			other = life.prevID
		}
		if other == "" {
			fmt.Fprintln(a.Stdout, "Diff: no previous scan of this target set")
		} else if err := a.printDiff(ctx, other, scan.ID); err != nil {
			return scan, ExitUsage, err
		}
	}
	for _, v := range violations {
		fmt.Fprintln(a.Stdout, "POLICY FAIL:", v)
	}
	if policy != nil && len(violations) == 0 {
		fmt.Fprintln(a.Stdout, "POLICY PASS:", policy.Path)
	}
	return scan, scan.ExitCode, nil
}

type lifecycleResult struct {
	prevID     string
	fixed      int
	accepted   int
	suppressed int
	reverted   []store.Reverted
}

// applyLifecycle runs baseline suppression, accept-risk application (expired
// acceptances revert to open and are audited) and fixed-marking against the
// previous scan of the same target set.
func (a *App) applyLifecycle(ctx context.Context, scan *domain.Scan, baseline *config.Baseline, baselinePath string) (lifecycleResult, error) {
	var res lifecycleResult
	var fps, rules []string
	if baseline != nil {
		fps, rules = baseline.Fingerprints, baseline.Rules
	}
	sup, _, err := a.Store.ApplyBaseline(ctx, scan.ID, fps, rules)
	if err != nil {
		return res, fmt.Errorf("baseline: %w", err)
	}
	res.suppressed = sup
	if baseline != nil {
		_ = a.Audit.Log(ctx, audit.ActionBaseline, scan.ID, map[string]any{"path": baselinePath, "fingerprints": len(fps), "rules": len(rules), "suppressed": sup})
	}
	applied, reverted, err := a.Store.ApplySuppressions(ctx, scan.ID, time.Now())
	if err != nil {
		return res, fmt.Errorf("suppressions: %w", err)
	}
	res.accepted, res.reverted = applied, reverted
	for _, r := range reverted {
		_ = a.Audit.Log(ctx, audit.ActionAcceptExpired, scan.ID, map[string]any{
			"suppression_id": r.Suppression.ID, "fingerprint": r.Suppression.Fingerprint, "rule_id": r.Suppression.RuleID, "asset": r.Suppression.AssetKey,
			"expired_at": r.Suppression.ExpiresAt, "reopened": r.Reopened,
		})
	}
	prev, ok, err := a.Store.PreviousScan(ctx, scan.TargetSetHash, scan.ID)
	if err != nil {
		return res, err
	}
	if ok {
		res.prevID = prev
		// Only engines that completed in this scan can vouch for a finding's
		// absence; skipped, failed or unselected engines leave theirs open.
		if res.fixed, err = a.Store.MarkFixed(ctx, scan.ID, okEngines(scan.Engines)); err != nil {
			return res, err
		}
	}
	return res, nil
}

// okEngines lists the engines whose run finished with status ok.
func okEngines(runs []domain.EngineRun) []string {
	var out []string
	for _, r := range runs {
		if r.Status == "ok" {
			out = append(out, r.Name)
		}
	}
	return out
}

// scanCounts tallies the stored findings of a scan by risk bucket.
func (a *App) scanCounts(ctx context.Context, scanID string) (risk.Counts, error) {
	var counts risk.Counts
	err := a.Store.ScanRiskRows(ctx, scanID, func(r store.RiskRow) {
		counts.Add(domain.Finding{Risk: r.Risk, Status: r.Status, KEV: r.KEV})
	})
	return counts, err
}

func policyInput(c risk.Counts, scan *domain.Scan) config.PolicyInput {
	return config.PolicyInput{
		OpenByBucket: map[string]int{"critical": c.Critical, "high": c.High, "medium": c.Medium, "low": c.Low, "info": c.Info},
		KEVOpen:      c.KEVOpen, Score: scan.Posture.Score, Partial: scan.Partial, Engines: scan.Engines,
	}
}

// printDiff prints new/fixed findings between two scans (a -> b).
func (a *App) printDiff(ctx context.Context, from, to string) error {
	d, err := a.Store.DiffScans(ctx, from, to)
	if errors.Is(err, store.ErrNotFound) {
		return exitf(ExitUsage, "%v", err)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Diff %s -> %s: %d new, %d fixed, %d unchanged\n", from, to, len(d.New), len(d.Fixed), d.Unchanged)
	const maxList = 200
	list := func(label string, fps []string) {
		for i, fp := range fps {
			if i >= maxList {
				fmt.Fprintf(a.Stdout, "  ... %d more\n", len(fps)-maxList)
				return
			}
			f, err := a.Store.GetFinding(ctx, fp)
			if err != nil {
				fmt.Fprintf(a.Stdout, "  %s %s\n", label, fp[:16])
				continue
			}
			fmt.Fprintf(a.Stdout, "  %s [%3d] %-28s %s %s\n", label, f.Risk, f.RuleID, f.AssetKey, f.Location)
		}
	}
	list("NEW  ", d.New)
	list("FIXED", d.Fixed)
	return nil
}

// redact runs s through the app redactor (identity when none is set).
func (a *App) redact(s string) string {
	if a.Redactor == nil {
		return s
	}
	return a.Redactor.Redact(s)
}

// redactErr redacts an error's message for display and audit while keeping
// the RefusalError type (and so the exit code) intact.
func (a *App) redactErr(err error) error {
	if err == nil {
		return nil
	}
	var r *safety.RefusalError
	if errors.As(err, &r) {
		return &safety.RefusalError{Code: r.Code, Target: a.redact(r.Target), Reason: a.redact(r.Reason)}
	}
	if red := a.redact(err.Error()); red != err.Error() {
		return errors.New(red)
	}
	return err
}

func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

var consentRank = map[string]int{domain.ConsentLocal: 0, domain.ConsentPrivateRange: 1, domain.ConsentDNSTXT: 2, domain.ConsentWellKnown: 2, domain.ConsentCloudAllowlist: 2, domain.ConsentInteractive: 3}

func strongerConsent(a, b string) string {
	if consentRank[b] > consentRank[a] {
		return b
	}
	return a
}

func mergeRun(a, b domain.EngineRun) domain.EngineRun {
	if a.Name == "" {
		return b
	}
	a.Duration += b.Duration
	if b.Status != "ok" && a.Status == "ok" {
		a.Status, a.Error = b.Status, b.Error
	}
	return a
}

func (a *App) planSummary(ctx context.Context, engs []engine.Engine, t domain.Target, o engine.Options) string {
	var lines []string
	for _, e := range engs {
		p, err := e.Plan(ctx, t, o)
		if err != nil {
			lines = append(lines, fmt.Sprintf("  %s: plan failed: %v", e.Name(), err))
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s: %s (~%s)", e.Name(), p.Summary, p.EstDuration.Round(time.Second)))
	}
	return strings.Join(lines, "\n")
}

// ackPrompt asks an interactive user for the authorization acknowledgment
// when neither scnr.yaml nor --ack-authorized provides one. Acceptance
// covers this run only and is not recorded; declining (or unreadable
// input) falls through to the gate, which refuses with E_ACK_REQUIRED.
func (a *App) ackPrompt() bool {
	fmt.Fprintf(a.Stdout, "\n%s\nType \"yes\" to confirm, or anything else to cancel: ", config.AckText)
	rd := bufio.NewReader(a.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(line), "yes")
}

// consentPrompt is the interactive public-target consent: show the plan,
// require the user to type the hostname/IP back.
func (a *App) consentPrompt(_ context.Context, t domain.Target, plan string) (bool, error) {
	want := t.Hostname
	if want == "" {
		want = t.Value
	}
	if t.Type == domain.TargetCloud {
		// want is the confirmed account id (the gate set Hostname to it).
		fmt.Fprintf(a.Stdout, "\n%s\n\nThis account is not listed in cloud.aws.accounts. You must own it or have written permission to assess it.\nType the account ID (%s) to continue, or anything else to cancel: ", plan, want)
	} else {
		fmt.Fprintf(a.Stdout, "\n%s is a PUBLIC target. Plan:\n%s\n\nYou must own this system or have written permission to test it.\nType the target (%s) to confirm, or anything else to cancel: ", t.Raw, plan, want)
	}
	rd := bufio.NewReader(a.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil && line == "" {
		return false, errors.New("no consent input")
	}
	return strings.EqualFold(strings.TrimSpace(line), want), nil
}

func (a *App) progress(name string, run *domain.EngineRun) {
	a.progressMu.Lock()
	defer a.progressMu.Unlock()
	if run.Status == "running" {
		fmt.Fprintf(a.Stderr, "  %-8s running...\n", name)
		return
	}
	line := fmt.Sprintf("  %-8s %s (%s)", name, run.Status, run.Duration.Round(time.Millisecond))
	if run.Error != "" {
		line += ": " + run.Error
	}
	fmt.Fprintln(a.Stderr, line)
}

func (a *App) printSummary(ctx context.Context, scan *domain.Scan, n int, paths []string) {
	w := a.Stdout
	fmt.Fprintf(w, "\nScan %s finished: %d finding(s). %s\n", scan.ID, n, report.ScoreLine(*scan))
	top, _ := a.Store.ListFindings(ctx, store.FindingFilter{ScanID: scan.ID, Status: domain.StatusOpen, Limit: 5})
	if len(top) > 0 {
		fmt.Fprintln(w, "Fix these first:")
		for i, f := range top {
			fmt.Fprintf(w, "  %d. [%3d] %s — %s\n", i+1, f.Risk, f.Title, firstLine(f.HowToFix))
		}
	}
	for _, p := range paths {
		fmt.Fprintf(w, "Report: %s\n", p)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
