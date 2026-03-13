package kernel

import "strings"

// BucketRef is a normalized S3 bucket identity value object.
// It consolidates bucket name extraction from ARN, model ID, and S3 URI formats.
type BucketRef struct {
	name string
}

// NewBucketRef creates a BucketRef by stripping any known S3 prefix and normalizing.
func NewBucketRef(input string) BucketRef {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.TrimPrefix(s, "arn:aws:s3:::")
	s = strings.TrimPrefix(s, "aws:s3:::")
	s = strings.TrimPrefix(s, "s3://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return BucketRef{name: s}
}

// Name returns the bare bucket name.
func (r BucketRef) Name() string { return r.name }

// ARN returns the full S3 ARN: "arn:aws:s3:::<name>".
func (r BucketRef) ARN() string { return "arn:aws:s3:::" + r.name }

// ModelID returns the storage model identifier: "aws:s3:::<name>".
func (r BucketRef) ModelID() string { return "aws:s3:::" + r.name }

// String returns the bare bucket name.
func (r BucketRef) String() string { return r.name }

// IsEmpty reports whether the bucket name is empty.
func (r BucketRef) IsEmpty() bool { return r.name == "" }

// Equals reports whether two BucketRefs refer to the same bucket.
func (r BucketRef) Equals(other BucketRef) bool { return r.name == other.name }
