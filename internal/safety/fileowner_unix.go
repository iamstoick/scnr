//go:build !windows

package safety

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
)

// checkFilePrivate requires mode exactly 0600 and ownership by the
// current uid.
func checkFilePrivate(path string, fi os.FileInfo) error {
	if fi.Mode().Perm() != 0o600 {
		return fmt.Errorf("auth file %s: mode is %04o, must be 0600 (chmod 600 %s)", path, fi.Mode().Perm(), path)
	}
	return checkFileOwner(path, fi)
}

// checkFileOwner requires the file to be owned by the current uid.
func checkFileOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("auth file %s: cannot stat owner", path)
	}
	if int(st.Uid) != os.Geteuid() {
		owner := fmt.Sprint(st.Uid)
		if u, err := user.LookupId(owner); err == nil {
			owner = u.Username
		}
		return fmt.Errorf("auth file %s: owned by %s, must be owned by the current user", path, owner)
	}
	return nil
}
