//go:build !linux && !darwin

// Package fsstat reports the free space of the filesystem holding a path.
package fsstat

import "errors"

// Usage is not available on this platform.
func Usage(string) (free, total uint64, err error) {
	return 0, 0, errors.New("fsstat: not supported on this platform")
}

// Supported reports whether Usage works on this platform.
const Supported = false
