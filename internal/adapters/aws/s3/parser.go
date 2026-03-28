package s3

import (
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// ParseS3Reference strips S3-specific prefixes (ARN, model ID, S3 URI)
// from input and returns a clean BucketRef.
func ParseS3Reference(input string) kernel.BucketRef {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.TrimPrefix(s, "arn:aws:s3:::")
	s = strings.TrimPrefix(s, "aws:s3:::")
	s = strings.TrimPrefix(s, "s3://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return kernel.NewBucketRef(s)
}
