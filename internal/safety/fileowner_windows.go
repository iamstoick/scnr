//go:build windows

package safety

import (
	"os"
)

// checkFilePrivate is a no-op on Windows: there is no uid to compare and
// Go maps Windows ACLs to 0666/0444 coarsely, so no mode check applies.
// Auth files on Windows rely on the user's profile-directory ACLs.
func checkFilePrivate(path string, fi os.FileInfo) error { return nil }
