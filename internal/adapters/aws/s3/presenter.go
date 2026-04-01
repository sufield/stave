package s3

import "github.com/sufield/stave/internal/core/kernel"

// ARN returns the full S3 ARN for a bucket: "arn:aws:s3:::<name>".
func ARN(ref kernel.BucketRef) string {
	return "arn:aws:s3:::" + ref.Name()
}
