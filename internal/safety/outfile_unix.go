//go:build unix

package safety

import "syscall"

// noFollow makes open(2) fail on a symlink at the final path component.
const noFollow = syscall.O_NOFOLLOW
