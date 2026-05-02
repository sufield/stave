package s3

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// ErrEmptyS3Reference is returned by ParseS3Reference when the input
// is empty or strips down to an empty bucket name. Tagged so callers
// can distinguish "no input" from "input that yielded a bad shape".
var ErrEmptyS3Reference = errors.New("s3: reference is empty")

// ParseS3Reference strips S3-specific prefixes (ARN, model ID, S3 URI)
// from input and returns a clean BucketRef.
//
// Returns ErrEmptyS3Reference (or a wrapped form) when the input is
// empty or when stripping prefixes leaves nothing — the previous
// shape returned a zero BucketRef which serialised back as
// "arn:aws:s3:::" downstream and matched no asset, producing
// silent-no-op enforcement for malformed input.
func ParseS3Reference(input string) (kernel.BucketRef, error) {
	s := strings.ToLower(strings.TrimSpace(input))
	if s == "" {
		return kernel.BucketRef{}, ErrEmptyS3Reference
	}
	s = strings.TrimPrefix(s, "arn:aws:s3:::")
	s = strings.TrimPrefix(s, "aws:s3:::")
	s = strings.TrimPrefix(s, "s3://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return kernel.BucketRef{}, fmt.Errorf("s3: reference %q has empty bucket after stripping prefixes: %w", input, ErrEmptyS3Reference)
	}
	return kernel.NewBucketRef(s), nil
}
