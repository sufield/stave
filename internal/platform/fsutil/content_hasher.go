package fsutil

import appcontracts "github.com/sufield/stave/internal/app/contracts"

// FSContentHasher implements ContentHasher using filesystem I/O.
type FSContentHasher struct{}

var _ appcontracts.ContentHasher = FSContentHasher{}

// HashDir returns a deterministic hash of files matching the given extensions.
func (FSContentHasher) HashDir(path string, exts ...string) (string, error) {
	d, err := HashDirByExt(path, exts...)
	return string(d), err
}

// HashFile returns the SHA-256 hash of a single file.
func (FSContentHasher) HashFile(path string) (string, error) {
	d, err := HashFile(path)
	return string(d), err
}
