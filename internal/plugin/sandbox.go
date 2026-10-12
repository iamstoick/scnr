package plugin

// Sandbox wraps plugin execution in an OS mechanism. Wrap returns the
// argv PREFIX (wrapper plus its flags); the engine appends the verified
// binary path and tool args, so the wrapper can never smuggle a
// different executable. A nil Sandbox means no wrapper is available.
type Sandbox interface {
	// Name is the wrapper name for versions, coverage and audit
	// ("bwrap", "sandbox-exec").
	Name() string
	// Wrap builds the wrapper prefix binding target read-only and
	// scratch read-write. net is reserved (always false: plugins never
	// get raw network; scoped HTTP goes through the broker socket,
	// which Unix-domain isolation leaves untouched).
	Wrap(binary, target, scratch string, net bool) ([]string, error)
}
