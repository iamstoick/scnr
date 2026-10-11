//go:build windows

package sched

// UnsupportedLocker refuses: the daemon is Unix-only in this version.
type UnsupportedLocker struct{}

// SystemLocker is the locker for this platform.
var SystemLocker Locker = UnsupportedLocker{}

func (UnsupportedLocker) TryLock(string) (func() error, error) {
	return nil, ErrUnsupported
}
