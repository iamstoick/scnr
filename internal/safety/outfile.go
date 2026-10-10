package safety

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// OutputFileMode is the permission of files scnr writes for the user
// (reports, SBOMs): owner read/write, group read, nothing for others.
const OutputFileMode = 0o640

// CreateOutputFile opens a user-supplied output path for writing and
// truncates it. It never writes through a symlink (an existing link is
// refused by Lstat and, on platforms that have it, O_NOFOLLOW closes the
// check-then-open window) and never truncates a non-regular file such as a
// device or FIFO. Every --out/--output path in the CLI goes through here so
// a report can only ever replace a regular file the user named.
func CreateOutputFile(p string) (*os.File, error) {
	st, err := os.Lstat(p)
	switch {
	case err == nil && st.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s: is a symbolic link; refusing to write through it", p)
	case err == nil && !st.Mode().IsRegular():
		return nil, fmt.Errorf("%s: exists and is not a regular file", p)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|noFollow, OutputFileMode)
	if err != nil {
		return nil, err
	}
	// The open itself may have raced with a rename; confirm what we hold.
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		if err == nil {
			err = fmt.Errorf("%s: not a regular file after open", p)
		}
		return nil, err
	}
	return f, nil
}
