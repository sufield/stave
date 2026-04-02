package ports

// ContentHasher computes reproducible digests over file system paths.
type ContentHasher interface {
	HashDir(path string, exts ...string) (string, error)
	HashFile(path string) (string, error)
}
