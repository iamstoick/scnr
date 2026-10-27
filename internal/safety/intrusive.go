package safety

import (
	"context"
	"errors"
	"fmt"

	"github.com/iamstoick/scnr/internal/domain"
)

// IntrusiveGate decides, per target, whether active checks may run: DAST
// probes for URL targets, database vulnerability probes for host
// targets. All three must hold: --allow-intrusive was passed, the target
// matches scope.intrusive_allow (deny still wins), and the target is
// private or carries a non-expired ownership verification. Interactive
// consent alone is never sufficient for intrusive checks on public
// targets. CIDR targets are refused: multi-host login-attempt loops are
// never started implicitly; narrow to one --type host address instead.
type IntrusiveGate struct {
	Scope    *Scope
	Verified VerifiedFunc
}

// Decide evaluates the intrusive rules for a target the Gate already
// allowed. ok=false with a nil error is a refusal with a human reason;
// err != nil means the decision itself failed (verification lookup).
func (g *IntrusiveGate) Decide(ctx context.Context, d *Decision, allowFlag bool) (ok bool, reason string, err error) {
	if d == nil {
		return false, "", errors.New("intrusive gate: nil decision")
	}
	if !allowFlag {
		return false, "pass --allow-intrusive to run active checks", nil
	}
	if d.Target.Type != domain.TargetURL && d.Target.Type != domain.TargetHost {
		return false, "active checks apply to URL and single-host targets only — narrow a range to one --type host address to use them", nil
	}
	host := d.Target.Hostname
	if host == "" {
		host = d.Target.Value
	}
	rawURL := d.Target.Value
	if denied, by := g.Scope.Denied(host, d.Addrs, rawURL); denied {
		return false, "matches deny entry " + by + "; remove it from scope.deny in scnr.yaml to permit active checks", nil
	}
	if !g.Scope.IntrusiveAllowed(host, d.Addrs, rawURL) {
		return false, fmt.Sprintf("not in scope.intrusive_allow; add %q there to permit active checks", host), nil
	}
	if !d.Public {
		return true, "", nil
	}
	if g.Verified == nil {
		return false, "cannot confirm ownership verification for a public target; run `scnr verify " + host + " --check` first", nil
	}
	ok, err = g.Verified(ctx, host)
	if err != nil {
		return false, "", fmt.Errorf("verification lookup: %w", err)
	}
	if !ok {
		return false, fmt.Sprintf("public target needs ownership verification for active checks (interactive consent is not enough): run `scnr verify %s`", host), nil
	}
	return true, "", nil
}
