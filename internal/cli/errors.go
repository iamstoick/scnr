package cli

import (
	"errors"
	"strings"

	"github.com/iamstoick/scnr/internal/safety"
	"github.com/iamstoick/scnr/internal/target"
)

// userFacingMessage reframes errors for newcomers: refusals and
// classification failures get their plain-English guidance, and every other
// error keeps its detail but gains a next step instead of standing alone.
func userFacingMessage(err error) string {
	if err == nil {
		return ""
	}
	var refusal *safety.RefusalError
	if errors.As(err, &refusal) {
		return refusal.Friendly()
	}
	var ambiguous *target.AmbiguousError
	if errors.As(err, &ambiguous) {
		return ambiguous.Friendly()
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	// Already actionable: it names a command, flag, or fix.
	if strings.Contains(lower, "run `") || strings.Contains(lower, "pass --") ||
		strings.Contains(lower, "use --") || strings.Contains(lower, "see `") ||
		strings.Contains(lower, "try ") || strings.Contains(lower, "tip:") ||
		strings.Contains(lower, "what to do") {
		return msg
	}
	if strings.HasPrefix(lower, "scope file:") {
		return msg + "\n\nTip: open scnr.yaml and fix the reported line, then run `scnr scope check <target>` to test it. " +
			"Run `scnr scope init --out scnr.yaml.new` to see a fresh example (it never overwrites)."
	}
	if strings.HasPrefix(msg, "--policy:") || strings.HasPrefix(msg, "--baseline:") || strings.HasPrefix(msg, "--templates:") {
		return msg + "\n\nTip: check the file path and format, then re-run. See `scnr scan --help` for examples."
	}
	return msg + "\n\nTip: run `scnr doctor` to check your setup, or add --help to your command for usage."
}
