package storage

import "github.com/sufield/stave/internal/domain/kernel"

// S3BucketRefModel represents a reference to an S3 bucket from an external source
// (DNS CNAME, CDN origin, application config). Used for bucket takeover detection
// via CTL.S3.BUCKET.TAKEOVER.001.
//
// The JSON tags match the observation schema field paths that the control predicate
// evaluates: properties.s3_ref.bucket_exists, properties.s3_ref.bucket_owned.
type S3BucketRefModel struct {
	Endpoint     string `json:"endpoint"`
	Bucket       string `json:"bucket"`
	BucketExists bool   `json:"bucket_exists"`
	BucketOwned  bool   `json:"bucket_owned"`
}

// BuildBucketRefModel creates a bucket reference model with normalized bucket identity.
func BuildBucketRefModel(endpoint string, bucket kernel.BucketRef, exists, owned bool) S3BucketRefModel {
	return S3BucketRefModel{
		Endpoint:     endpoint,
		Bucket:       bucket.Name(),
		BucketExists: exists,
		BucketOwned:  owned,
	}
}
