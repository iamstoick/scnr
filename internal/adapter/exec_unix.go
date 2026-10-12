//go:build !windows

package adapter

import (
	"os/exec"
	"syscall"
)

func setNewProcessGroup(cmd *exec.Cmd, enable bool) {
	if enable {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
}

// killProcessGroup SIGKILLs the process group led by pid (the child set
// up with Setpgid), reaping forked grandchildren.
func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
