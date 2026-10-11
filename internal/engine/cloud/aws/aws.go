// Package aws is the native AWS posture engine: read-only API calls
// through the SDK's middleware stack with a read-only guard, a call budget
// and pagination caps, bound to the account the credentials belong to
// (sts:GetCallerIdentity before anything else). See SAFETY.md item 16.
package aws

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"golang.org/x/sync/errgroup"

	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

//go:embed rules/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "cloud-aws"

// Scheme prefix of the target value.
const Scheme = "aws://"

// Run-shape constants.
const (
	regionParallel = 4
	checkTimeout   = 2 * time.Minute
	userAgent      = "scnr-cloud-aws"
)

// Engine implements engine.Engine for aws:// targets.
type Engine struct {
	rules engine.RuleSet
	// Config is cloud.aws from the scope file.
	Config config.CloudAWS
	// Test hooks: a BaseEndpoint for every service client and the endpoint
	// allowlist to use instead of *.amazonaws.com (which also allows loopback).
	// The CLI never sets either (TestCLIDoesNotExposeEndpointOverride).
	BaseEndpoint  string
	EndpointHosts []string
	// HTTPTimeout for one API request; zero means 60s.
	HTTPTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*session // by profile; filled by Identity, reused by Run
}

// New loads the rules.
func New(cfg config.CloudAWS) (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rs, Config: cfg, sessions: map[string]*session{}}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Rules exposes the rule prose (the prowler adapter dedupes onto it).
func (e *Engine) Rules() engine.RuleSet { return e.rules }

// Supports aws:// cloud targets.
func (e *Engine) Supports(t domain.Target) bool {
	return t.Type == domain.TargetCloud && strings.HasPrefix(t.Value, Scheme)
}

// Plan implements engine.Engine.
func (e *Engine) Plan(_ context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	regions := "the account's enabled regions"
	if len(e.Config.Regions) > 0 {
		regions = strings.Join(e.Config.Regions, ", ")
	}
	return engine.Plan{
		Summary:     fmt.Sprintf("%d read-only AWS posture checks (IAM, S3, EC2, RDS, CloudTrail, KMS) across %s; at most %d API calls", len(checkNames()), regions, budgetFor(o.Profile)),
		EstRequests: 200, EstDuration: 3 * time.Minute, Network: true,
	}, nil
}

// profileOf extracts the profile from aws://<profile> (empty for aws://
// and for the post-gate aws://<account> form, where the profile has moved
// to Labels["profile"]).
func profileOf(t domain.Target) string {
	if p := t.Labels["profile"]; p != "" {
		return p
	}
	rest := strings.TrimPrefix(t.Value, Scheme)
	if cloudAccountRe.MatchString(rest) {
		return ""
	}
	return rest
}

// accountOf returns the confirmed account from aws://<account>, or "".
func accountOf(t domain.Target) string {
	rest := strings.TrimPrefix(t.Value, Scheme)
	if cloudAccountRe.MatchString(rest) {
		return rest
	}
	return ""
}

var cloudAccountRe = accountIDRe

func budgetFor(p engine.Profile) int64 {
	if p.Name == "deep" {
		return budgetDeep
	}
	return budgetStandard
}

func rateFor(p engine.Profile) int {
	if p.Name == "deep" {
		return rateDeep
	}
	return rateStandard
}

// Identity is the safety.CloudIdentityFunc: resolve the credential chain
// for the target's profile, issue one sts:GetCallerIdentity and remember
// the resolved credentials so Run uses the very same object.
func (e *Engine) Identity(ctx context.Context, t domain.Target) (safety.CloudIdentity, error) {
	s, err := e.session(ctx, profileOf(t), engine.Profile{})
	if err != nil {
		return safety.CloudIdentity{}, err
	}
	return s.identity, nil
}

// session returns the cached session for profile or builds one: plan the
// chain, build the HTTP client, resolve credentials, confirm identity.
func (e *Engine) session(ctx context.Context, profile string, p engine.Profile) (*session, error) {
	e.mu.Lock()
	s, ok := e.sessions[profile]
	e.mu.Unlock()
	if ok {
		return s, nil
	}
	plan, err := planCredentials(ctx, profile, chainOptions{instanceCredentials: e.Config.InstanceCredentials})
	if err != nil {
		return nil, err
	}
	timeout := e.HTTPTimeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	hc, err := newHTTPClient(e.EndpointHosts, timeout, userAgent)
	if err != nil {
		return nil, err
	}
	s = &session{http: hc, budget: newBudget(budgetFor(p)), rate: rateFor(p), profName: p.Name}
	if e.BaseEndpoint != "" {
		s.base = aws.String(e.BaseEndpoint)
	}
	prov, err := plan.provider(s, userAgent)
	if err != nil {
		return nil, err
	}
	s.creds = aws.NewCredentialsCache(prov)
	account, arn, err := s.callerIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("sts:GetCallerIdentity (%s): %w", plan.Describe(), cleanErr(err))
	}
	s.identity = safety.CloudIdentity{Provider: "aws", Account: account, Principal: arn, Source: plan.source}
	e.mu.Lock()
	e.sessions[profile] = s
	e.mu.Unlock()
	return s, nil
}

// cleanErr strips control characters from an SDK error (they can embed
// request details) so it is safe to log; the redactor runs on it later.
func cleanErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(safety.StripControl(err.Error()))
}

// Run implements engine.Engine. The target must be the gate's rewritten
// aws://<account> form; the session's identity must match it.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	s, err := e.session(ctx, profileOf(t), o.Profile)
	if err != nil {
		return err
	}
	account := accountOf(t)
	if account == "" {
		return errors.New("cloud/aws: target was not confirmed by the gate (expected aws://<account-id>)")
	}
	if s.identity.Account != account {
		return fmt.Errorf("cloud/aws: credentials belong to account %s, scan was authorised for %s", s.identity.Account, account)
	}
	// The gate cached this session through Identity with an empty profile;
	// install the run's budget and rate before any check runs.
	s.setProfile(o.Profile)
	red := o.Redactor
	if red == nil {
		red = safety.NewRedactor()
	}
	run := &run{e: e, s: s, account: account, red: red, emit: emit, cov: &coverage{}, log: o.Log}
	if err := run.execute(ctx); err != nil {
		return err
	}
	// The account must still be the one authorised; a credential rotation
	// to another account mid-run is a misconfiguration, not a partial result.
	s.budget.releaseReserve()
	acct, _, err := s.callerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("cloud/aws: identity re-check failed: %w", cleanErr(err))
	}
	if acct != account {
		return fmt.Errorf("cloud/aws: identity changed during the run (now account %s, authorised %s)", acct, account)
	}
	if reason := run.cov.reason(); reason != "" {
		return &engine.PartialError{Reason: reason}
	}
	return nil
}

// run is the per-scan state.
type run struct {
	e       *Engine
	s       *session
	account string
	red     *safety.Redactor
	emit    engine.EmitFunc
	cov     *coverage
	log     interface {
		Debug(msg string, args ...any)
	}
}

// execute runs the global checks, discovers regions, then the regional
// checks with bounded parallelism. A BudgetExceededError anywhere stops
// everything else and marks the run partial.
func (r *run) execute(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	global := r.s.clients(globalRegion)
	for _, c := range globalChecks {
		if r.runCheck(ctx, c, global) {
			return r.truncationFindings(ctx)
		}
	}
	regions, err := r.regions(ctx, global)
	if err != nil {
		if r.budgetHit(err) {
			return r.truncationFindings(ctx)
		}
		r.cov.fail("regions", "", cleanErr(err))
		return r.truncationFindings(ctx)
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(regionParallel)
	var stop sync.Once
	for _, region := range regions {
		cl := r.s.clients(region)
		g.Go(func() error {
			for _, c := range regionalChecks {
				if gctx.Err() != nil {
					return nil
				}
				if r.runCheck(gctx, c, cl) {
					stop.Do(cancel)
					return nil
				}
			}
			return nil
		})
	}
	_ = g.Wait()
	if err := ctx.Err(); err != nil && !r.cov.budget {
		return err
	}
	return r.truncationFindings(context.WithoutCancel(ctx))
}

// runCheck runs one check with its timeout; a failure is recorded in
// coverage, never fatal. It returns true when the budget is gone.
func (r *run) runCheck(ctx context.Context, c check, cl *clients) (budgetGone bool) {
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	err := c.fn(cctx, r, cl)
	if err == nil {
		return false
	}
	if r.budgetHit(err) {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	r.cov.fail(c.name, cl.region, cleanErr(err))
	if r.log != nil {
		r.log.Debug("cloud/aws check failed", "check", c.name, "region", cl.region, "error", r.red.Clean(err.Error(), 500))
	}
	return false
}

func (r *run) budgetHit(err error) bool {
	var be *BudgetExceededError
	if errors.As(err, &be) {
		r.cov.mu.Lock()
		r.cov.budget = true
		r.cov.mu.Unlock()
		return true
	}
	return false
}

// regions returns the configured regions or the account's enabled ones
// (capped at config.MaxCloudRegions, sorted for determinism).
func (r *run) regions(ctx context.Context, cl *clients) ([]string, error) {
	if len(r.e.Config.Regions) > 0 {
		return r.e.Config.Regions, nil
	}
	out, err := cl.ec2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	var regions []string
	for _, rg := range out.Regions {
		if n := aws.ToString(rg.RegionName); regionRe.MatchString(n) {
			regions = append(regions, n)
		}
	}
	sort.Strings(regions)
	if len(regions) > config.MaxCloudRegions {
		r.cov.truncate(truncation{list: "regions", items: len(regions)})
		regions = regions[:config.MaxCloudRegions]
	}
	return regions, nil
}

// truncationFindings emits cloud.aws.inventory-truncated once per capped
// list (and once for the budget) after the checks have run.
func (r *run) truncationFindings(ctx context.Context) error {
	r.cov.mu.Lock()
	trunc := append([]truncation(nil), r.cov.truncated...)
	budget := r.cov.budget
	r.cov.mu.Unlock()
	for _, t := range trunc {
		loc := fmt.Sprintf("arn:aws:scnr:%s:%s:inventory/%s", t.region, r.account, t.list)
		if err := r.finding(RuleInventoryTruncated, loc, domain.Confirmed,
			fmt.Sprintf("list=%s region=%s pages=%d items=%d cap_pages=%d cap_items=%d", t.list, t.region, t.pages, t.items, maxPages, maxItems)); err != nil {
			return err
		}
	}
	if budget {
		loc := fmt.Sprintf("arn:aws:scnr::%s:inventory/budget", r.account)
		if err := r.finding(RuleInventoryTruncated, loc, domain.Confirmed,
			fmt.Sprintf("API call budget of %d exhausted after %d calls; remaining checks were not run", r.s.budget.total, r.s.budget.used())); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// finding emits one finding: the rule's prose, the account asset, the ARN
// as location and a one-line structured summary (built only from the
// allowlisted fields the check read) as redacted evidence.
func (r *run) finding(ruleID, arn string, conf domain.Confidence, summary string) error {
	arn = safety.StripControl(arn)
	if arn == "" || len(arn) > 2048 {
		return nil
	}
	f := r.e.rules.NewFinding(ruleID, "aws:"+r.account, arn, conf)
	f.Evidence = []domain.Evidence{r.red.TextEvidence("cloud-api", arn, summary)}
	return r.emit(f)
}
