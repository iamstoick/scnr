//go:build !unix

package safety

// noFollow has no portable equivalent here; CreateOutputFile relies on its
// Lstat check alone (a check-then-open window remains on these platforms).
const noFollow = 0
