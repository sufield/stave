package storage

import "github.com/sufield/stave/internal/domain/kernel"

// VendorAWS is the canonical domain identifier for Amazon Web Services.
// Defined here in the adapter layer to keep vendor-specific constants
// out of the domain kernel.
const VendorAWS kernel.Vendor = "aws"

// TypeS3Bucket is the canonical asset type for AWS S3 buckets.
// Defined here in the adapter layer to keep vendor-specific strings
// out of the domain kernel.
const TypeS3Bucket kernel.AssetType = "aws_s3_bucket"

// TypeS3BucketRef is the asset type for external references to S3 buckets
// (DNS CNAME, CDN origin, application config). Used for bucket takeover detection.
const TypeS3BucketRef kernel.AssetType = "s3_bucket_reference"
