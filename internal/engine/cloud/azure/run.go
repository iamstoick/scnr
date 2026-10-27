package azure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

// apiVersion pins every ARM call: unversioned calls drift with the cloud.
const apiVersion = "2022-12-01"

// SourceInstance marks managed-identity logins in audit lines.
const SourceInstance = "managed-identity"

// Identity is the safety.CloudIdentityFunc: resolve the credential chain
// for the target, issue one subscription read, and remember the session so
// Run uses the very same login.
func (e *Engine) Identity(ctx context.Context, t domain.Target) (safety.CloudIdentity, error) {
	sub := accountOf(t)
	if sub == "" {
		sub = subscriptionOf(t)
	}
	if sub == "" || !subscriptionRe.MatchString(sub) {
		return safety.CloudIdentity{}, &safety.RefusalError{Code: safety.CodeCloudIdentity, Target: t.Raw, Reason: "azure:// needs a subscription id"}
	}
	cred, source, err := e.credential()
	if err != nil {
		return safety.CloudIdentity{}, err
	}
	s := e.newSession(cred, source)
	got, _, err := s.subscription(ctx, sub)
	if err != nil {
		return safety.CloudIdentity{}, err
	}
	if !strings.EqualFold(got, sub) {
		return safety.CloudIdentity{}, &safety.RefusalError{Code: safety.CodeCloudIdentity, Target: t.Raw, Reason: "identity call returned another subscription"}
	}
	e.mu.Lock()
	e.sessions[credKey(cred, source)] = s
	e.mu.Unlock()
	return safety.CloudIdentity{Provider: "azure", Account: got, Principal: principalName(source), Source: source}, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	sub := accountOf(t)
	if sub == "" {
		return &safety.RefusalError{Code: safety.CodeCloudIdentity, Target: t.Raw, Reason: "unconfirmed subscription; the gate must confirm it first"}
	}
	cred, source, err := e.credential()
	if err != nil {
		return err
	}
	e.mu.Lock()
	s, ok := e.sessions[credKey(cred, source)]
	e.mu.Unlock()
	if !ok {
		s = e.newSession(cred, source)
	}
	red := o.Redactor
	if red == nil {
		red = safety.NewRedactor()
	}
	var mu sync.Mutex
	safeEmit := func(f domain.Finding) error {
		mu.Lock()
		defer mu.Unlock()
		return emit(f)
	}
	r := &run{e: e, s: s, sub: sub, red: red, emit: safeEmit}
	if err := r.execute(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

// credKey separates sessions by login; tokens themselves are never keys.
func credKey(cred azcore.TokenCredential, source string) string {
	return fmt.Sprintf("%T/%s", cred, source)
}

// subscription names the subscription under test for evidence.
func (e *Engine) newSession(cred azcore.TokenCredential, source string) *session {
	base := "https://management.azure.com"
	hosts := []string{}
	if e.BaseEndpoint != "" {
		base = e.BaseEndpoint
		hosts = e.EndpointHosts
	}
	return &session{
		cred:   cred,
		source: source,
		budget: newBudget(budgetStd),
		client: newHTTPClient(hosts, e.HTTPTimeout),
		base:   base,
	}
}

type run struct {
	e     *Engine
	s     *session
	sub   string
	red   *safety.Redactor
	emit  engine.EmitFunc
	log   interface{ Debug(msg string, args ...any) }
	fails []string
	mu    sync.Mutex
}

// execute runs every check; one check's failure is recorded in coverage,
// never fatal. Budget exhaustion ends the run partial.
func (r *run) execute(ctx context.Context) error {
	for _, c := range checks {
		if err := ctx.Err(); err != nil {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		err := c.fn(cctx, r)
		cancel()
		if err == nil {
			continue
		}
		var be *BudgetExceededError
		if errors.As(err, &be) {
			return r.truncated()
		}
		r.fail(c.name, err)
	}
	if len(r.fails) > 0 {
		return r.truncated()
	}
	return nil
}

func (r *run) fail(check string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fails = append(r.fails, check+": "+r.red.Clean(err.Error(), 500))
}

func (r *run) truncated() error {
	loc := Scheme + r.sub
	f := r.e.rules.NewFinding("cloud.azure.inventory-truncated", "azure:"+r.sub, loc, domain.Confirmed)
	f.Evidence = []domain.Evidence{r.red.TextEvidence("response", loc, "coverage gaps: "+strings.Join(r.fails, "; "))}
	if err := r.emit(f); err != nil {
		return err
	}
	return &engine.PartialError{Reason: "azure coverage truncated: " + strings.Join(r.fails, "; ")}
}

// finding emits one confirmed finding on a resource id.
func (r *run) finding(ruleID, resourceID string, summary string) error {
	f := r.e.rules.NewFinding(ruleID, "azure:"+r.sub, resourceID, domain.Confirmed)
	f.Evidence = []domain.Evidence{r.red.TextEvidence("response", resourceID, summary)}
	return r.emit(f)
}
