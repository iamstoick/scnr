package aws

import (
	"context"
	"fmt"
	"regexp"
	"sync/atomic"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	"golang.org/x/time/rate"
)

// readOnlyOp is the only shape of operation name the posture clients may
// issue. readOnlyDeny lists operations that match the shape but create an
// artefact or a credential and are therefore refused as well.
var (
	readOnlyOp   = regexp.MustCompile(`^(Get|List|Describe|Head|Lookup)[A-Z]`)
	readOnlyDeny = map[string]bool{"GenerateCredentialReport": true, "GetSessionToken": true, "GetFederationToken": true}
)

// credentialOps are the operations the credential provider's STS client may
// issue. Together with readOnlyOp this is the complete set of operation
// names the package permits (TestAWSOperationsAreReadOnly pins the sources
// to the same two lists).
var credentialOps = map[string]bool{"AssumeRole": true, "AssumeRoleWithWebIdentity": true, "GetCallerIdentity": true}

// RefusedOperationError is returned, before anything is serialised, signed
// or sent, for an operation the guard does not allow.
type RefusedOperationError struct{ Op string }

func (e *RefusedOperationError) Error() string {
	return fmt.Sprintf("cloud/aws: operation %s refused: not a read-only operation (SAFETY.md item 16)", e.Op)
}

// ReadOnlyGuard sits in the Initialize step of every posture client.
type ReadOnlyGuard struct{}

// ID implements middleware.InitializeMiddleware.
func (ReadOnlyGuard) ID() string { return "scnrReadOnlyGuard" }

// HandleInitialize implements middleware.InitializeMiddleware.
func (ReadOnlyGuard) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
	op := awsmiddleware.GetOperationName(ctx)
	if !readOnlyOp.MatchString(op) || readOnlyDeny[op] {
		return middleware.InitializeOutput{}, middleware.Metadata{}, &RefusedOperationError{Op: op}
	}
	return next.HandleInitialize(ctx, in)
}

// credentialGuard is the ReadOnlyGuard replacement for the STS client the
// credential chain uses: an exact allowlist instead of the shape rule.
type credentialGuard struct{}

func (credentialGuard) ID() string { return "scnrCredentialGuard" }

func (credentialGuard) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
	op := awsmiddleware.GetOperationName(ctx)
	if !credentialOps[op] {
		return middleware.InitializeOutput{}, middleware.Metadata{}, &RefusedOperationError{Op: op}
	}
	return next.HandleInitialize(ctx, in)
}

// BudgetExceededError is returned once the scan-wide call budget is spent.
type BudgetExceededError struct{ Budget int64 }

func (e *BudgetExceededError) Error() string {
	return fmt.Sprintf("cloud/aws: API call budget of %d exhausted", e.Budget)
}

// budget is the scan-wide API call allowance shared by every client.
type budget struct {
	total     int64
	remaining atomic.Int64
	exhausted atomic.Bool
}

// newBudget reserves one call out of total for the end-of-run identity
// re-check (releaseReserve), so an exhausted budget cannot skip it.
func newBudget(total int64) *budget {
	b := &budget{total: total}
	b.remaining.Store(total - 1)
	return b
}

// releaseReserve returns the reserved call to the pool.
func (b *budget) releaseReserve() {
	b.remaining.Add(1)
	b.exhausted.Store(false)
}

// take consumes one call; false once the budget is gone. A refused take
// does not drive the counter further negative, so the reserve can be
// released later.
func (b *budget) take() bool {
	if b.exhausted.Load() {
		return false
	}
	if b.remaining.Add(-1) < 0 {
		b.remaining.Add(1)
		b.exhausted.Store(true)
		return false
	}
	return true
}

// used returns how many calls were made (capped at the total).
func (b *budget) used() int64 {
	r := b.remaining.Load()
	if r < 0 {
		r = 0
	}
	return b.total - r
}

// Meter sits in the Finalize step after the retryer, so every attempt
// (retries included) waits on the per-region rate limiter and spends one
// unit of the scan-wide budget.
type Meter struct {
	limiter *rate.Limiter
	budget  *budget
}

// ID implements middleware.FinalizeMiddleware.
func (Meter) ID() string { return "scnrMeter" }

// HandleFinalize implements middleware.FinalizeMiddleware.
func (m Meter) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	if !m.budget.take() {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, &BudgetExceededError{Budget: m.budget.total}
	}
	if err := m.limiter.Wait(ctx); err != nil {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, err
	}
	return next.HandleFinalize(ctx, in)
}
