package kernel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidBucket indicates the bucket name is not valid.
var ErrInvalidBucket = errors.New("invalid bucket name")

// bucketNameRe is an RFC 1123-style regex used by common object stores.
var bucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

// BucketRef is a normalized storage container identity value object.
type BucketRef struct {
	name string
}

// NewBucketRef creates a BucketRef from a bare bucket name.
func NewBucketRef(name string) BucketRef {
	return BucketRef{name: strings.ToLower(strings.TrimSpace(name))}
}

// Name returns the bare bucket name.
func (r BucketRef) Name() string { return r.name }

// String returns the bare bucket name.
func (r BucketRef) String() string { return r.name }

// IsEmpty reports whether the bucket name is empty.
func (r BucketRef) IsEmpty() bool { return r.name == "" }

// Equals reports whether two BucketRefs refer to the same bucket.
func (r BucketRef) Equals(other BucketRef) bool { return r.name == other.name }

// Validate checks that the normalized bucket name is safe for use in
// file paths and URLs. It applies RFC 1123-style rules used by common
// object stores: 3-63 lowercase alphanumeric/hyphen/dot characters, no "..".
func (r BucketRef) Validate() error {
	if strings.Contains(r.name, "..") || !bucketNameRe.MatchString(r.name) {
		return fmt.Errorf("%w: %q", ErrInvalidBucket, r.name)
	}
	return nil
}
