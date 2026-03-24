package fsutil

import "io/fs"

// SafeFileSystem implements fix.FileSystem using symlink-safe wrappers.
// Injected by the cmd layer into ArtifactWriter.
type SafeFileSystem struct {
	Overwrite    bool
	AllowSymlink bool
}

// MkdirAll creates directories with symlink safety checks.
func (s SafeFileSystem) MkdirAll(path string, perm fs.FileMode) error {
	return SafeMkdirAll(path, WriteOptions{Perm: perm, AllowSymlink: s.AllowSymlink})
}

// WriteFile writes data with symlink and overwrite protection.
func (s SafeFileSystem) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return SafeWriteFile(path, data, WriteOptions{Perm: perm, Overwrite: s.Overwrite, AllowSymlink: s.AllowSymlink})
}
