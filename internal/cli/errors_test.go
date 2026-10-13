package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/safety"
	"github.com/iamstoick/scnr/internal/target"
)

// Refusals surface the friendly guidance (not the raw CODE: target: reason),
// ambiguous targets explain --type, and every other error still gains a tip.
func TestUserFacingMessage(t *testing.T) {
	refusal := &safety.RefusalError{Code: safety.CodeScopeNotAllowed, Target: "geraldvillorente.com", Reason: "public address not in scope.allow"}
	if got := userFacingMessage(refusal); !strings.Contains(got, "approved list") || !strings.Contains(got, "scnr scope check") || !strings.Contains(got, "E_SCOPE_NOT_ALLOWED") {
		t.Fatalf("refusal not reframed:\n%s", got)
	}
	amb := &target.AmbiguousError{Raw: "does-not-exist.invalid", Candidates: []string{"host (does not resolve)", "path (does not exist)"}}
	if got := userFacingMessage(amb); !strings.Contains(got, "--type") || !strings.Contains(got, "E_TARGET_AMBIGUOUS") {
		t.Fatalf("ambiguous not reframed:\n%s", got)
	}
	// Wrapped refusals (ExitError chain) still reframe.
	wrapped := &ExitError{Code: ExitRefused, Err: refusal}
	var r *safety.RefusalError
	if !errors.As(wrapped, &r) || !strings.Contains(userFacingMessage(wrapped), "approved list") {
		t.Fatalf("wrapped refusal not reframed: %v", wrapped)
	}
	// Generic errors keep their detail and gain a next step.
	if got := userFacingMessage(errors.New("open database /tmp/x.db: permission denied")); !strings.Contains(got, "permission denied") || !strings.Contains(got, "scnr doctor") {
		t.Fatalf("generic error missing tip:\n%s", got)
	}
	// Already-actionable errors are left alone (no doubled tip).
	already := "credentials in the target URL are not supported; remove the user:password@ part and use --auth-file instead (see `scnr scan --help`)"
	if got := userFacingMessage(errors.New(already)); strings.Contains(got, "Tip: run `scnr doctor`") || got != already {
		t.Fatalf("actionable error rewritten:\n%s", got)
	}
}

// End to end: the reported `scan <public-host>` refusal guides instead of
// puzzling. Uses the package harness from cli_test.go.
func TestScanScopeRefusalGuidesUser(t *testing.T) {
	h := newHarness(t)
	h.res.hosts["public.test"] = []string{"203.0.113.10"}
	out := t.TempDir() + "/out"
	if code := h.run(t, "scan", "public.test", "--ack-authorized", "--non-interactive", "--out", out); code != ExitRefused {
		t.Fatalf("exit %d, want %d", code, ExitRefused)
	}
	errOut := h.stderr.String()
	for _, want := range []string{"approved list", "scnr scope check public.test", "scnr verify", "E_SCOPE_NOT_ALLOWED", "What to do next"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("stderr missing %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(errOut, "error: E_SCOPE_NOT_ALLOWED:") {
		t.Fatalf("stderr still leads with the raw code:\n%s", errOut)
	}
}
