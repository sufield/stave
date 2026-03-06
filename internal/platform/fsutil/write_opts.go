package fsutil

import "os"

// WriteOptions defines safety controls for write operations.
type WriteOptions struct {
	Perm         os.FileMode
	Overwrite    bool
	AllowSymlink bool
}

// DefaultWriteOpts returns conservative defaults (0o600, no overwrite, no symlinks)
// for sensitive output files like evaluations and reports.
func DefaultWriteOpts() WriteOptions {
	return WriteOptions{
		Perm:         0o600,
		Overwrite:    false,
		AllowSymlink: false,
	}
}

// ConfigWriteOpts returns defaults for configuration files (0o644, overwrite
// allowed, no symlinks). Config files use broader read permissions because
// they are typically checked into version control.
func ConfigWriteOpts() WriteOptions {
	return WriteOptions{
		Perm:         0o644,
		Overwrite:    true,
		AllowSymlink: false,
	}
}
