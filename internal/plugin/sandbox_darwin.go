//go:build darwin

package plugin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type sandboxExec struct{}

func (sandboxExec) Name() string { return "sandbox-exec" }

// DetectSandbox returns the sandbox-exec wrapper when present.
func DetectSandbox() Sandbox {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		return nil
	}
	return sandboxExec{}
}

func (sandboxExec) Wrap(binary, target, scratch string, net bool) ([]string, error) {
	profile := fmt.Sprintf(`(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-read* (subpath %[1]s) (subpath %[2]s))
(allow file-write* (subpath %[2]s))
(allow process-exec (literal %[3]s))
`, quoteProfile(target), quoteProfile(scratch), quoteProfile(binary))
	// The deny-all write sits BEFORE the scratch allow: sandbox rules
	// resolve last-match-wins, so this order keeps the scratch writable
	// while everything else stays read-only.
	path := filepath.Join(scratch, "plugin.sb")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		return nil, err
	}
	return []string{"sandbox-exec", "-f", path}, nil
}

// quoteProfile renders a path as a sandbox profile string literal.
func quoteProfile(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
