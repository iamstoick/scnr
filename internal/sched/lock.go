package sched

import "errors"
import "fmt"

// ErrUnsupported is returned where the daemon cannot run (Windows).
var ErrUnsupported = errors.New("daemon is not supported on this platform")

// LockedError reports a daemon already holding the home lock. PID is the
// recorded pid, or 0 when it could not be read.
type LockedError struct{ PID int }

func (e *LockedError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("already running (pid %d)", e.PID)
	}
	return "already running"
}

// Locker takes the home lock. The release func must be called on
// shutdown; the lock is held for the process lifetime.
type Locker interface {
	TryLock(path string) (release func() error, err error)
}
