//go:build !windows

package sched

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// FlockLocker holds an exclusive non-blocking flock on the lock file for
// as long as the returned release func is not called (closing the file
// releases the lock). The daemon pid is written into the file for
// diagnostics only.
type FlockLocker struct{}

// SystemLocker is the locker for this platform.
var SystemLocker Locker = FlockLocker{}

func (FlockLocker) TryLock(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &LockedError{PID: readPID(path)}
		}
		return nil, err
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return f.Close, nil
}

// readPID returns the pid recorded in the lock file, or 0 when the file
// is empty or unreadable (a daemon that just started, or a stale file).
func readPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
