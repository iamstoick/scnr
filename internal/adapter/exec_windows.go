//go:build windows

package adapter

import (
	"os/exec"
)

// Setpgid has no Windows equivalent; the context kill of the child is
// the only control.
func setNewProcessGroup(cmd *exec.Cmd, enable bool) {}

func killProcessGroup(pid int) {}
