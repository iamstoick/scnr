//go:build !linux && !darwin

package plugin

// DetectSandbox reports no wrapper on platforms without one (notably
// Windows): plugins run only under sandbox: best-effort, audited per run.
func DetectSandbox() Sandbox { return nil }
