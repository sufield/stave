package fsutil

import (
	"fmt"
	"os"
	"regexp"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// IsSymlink reports whether path is a symbolic link.
// Returns (false, nil) for non-existent paths.
func IsSymlink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return fi.Mode()&os.ModeSymlink != 0, nil
}

// bucketNameRe is an RFC 1123-style regex used by common object stores.
var testBucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

// ValidateBucket validates that name is a legal S3 bucket name.
func ValidateBucket(name string) error {
	if len(name) < 3 || !testBucketNameRe.MatchString(name) {
		return fmt.Errorf("%w: %q", kernel.ErrInvalidBucket, name)
	}
	// Reject ".." to prevent path traversal via bucket names.
	for i := 0; i < len(name)-1; i++ {
		if name[i] == '.' && name[i+1] == '.' {
			return fmt.Errorf("%w: %q", kernel.ErrInvalidBucket, name)
		}
	}
	return nil
}
