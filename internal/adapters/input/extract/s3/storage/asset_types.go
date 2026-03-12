package storage

import "github.com/sufield/stave/internal/domain/kernel"

// TypeS3Bucket is the canonical asset type for AWS S3 buckets.
// Defined here in the adapter layer to keep vendor-specific strings
// out of the domain kernel.
const TypeS3Bucket kernel.AssetType = "aws_s3_bucket"
