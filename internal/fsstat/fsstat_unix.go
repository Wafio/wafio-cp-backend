//go:build linux || darwin

// Package fsstat reports the free space of the filesystem holding a path.
package fsstat

import "golang.org/x/sys/unix"

// Usage returns the space available to unprivileged users and the total size
// of the filesystem that holds path.
func Usage(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec,unconvert // block size is positive; int64 on linux, uint32 on darwin
	return st.Bavail * bs, st.Blocks * bs, nil
}

// Supported reports whether Usage works on this platform.
const Supported = true
