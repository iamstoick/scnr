//go:build linux

package plugin

import (
	"os"
	"os/exec"
)

type bwrap struct{}

func (bwrap) Name() string { return "bwrap" }

// DetectSandbox returns the bwrap wrapper when the binary is present.
func DetectSandbox() Sandbox {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return nil
	}
	return bwrap{}
}

func (bwrap) Wrap(binary, target, scratch string, net bool) ([]string, error) {
	argv := []string{"bwrap",
		"--unshare-all", "--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/lib", "/lib",
	}
	if st, err := os.Stat("/lib64"); err == nil && st.IsDir() {
		argv = append(argv, "--ro-bind", "/lib64", "/lib64")
	}
	// Non-merged-/usr systems keep real /bin and /sbin.
	for _, d := range []string{"/bin", "/sbin"} {
		if st, err := os.Lstat(d); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			argv = append(argv, "--ro-bind", d, d)
		}
	}
	argv = append(argv,
		"--ro-bind", target, target,
		"--bind", scratch, scratch,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--chdir", scratch,
		"--unshare-net",
		"--",
	)
	// Contain fork bombs and fd exhaustion where prlimit exists.
	if prlimit, err := exec.LookPath("prlimit"); err == nil {
		argv = append([]string{prlimit, "--nproc=128", "--nofile=1024", "--"}, argv...)
	}
	return argv, nil
}
