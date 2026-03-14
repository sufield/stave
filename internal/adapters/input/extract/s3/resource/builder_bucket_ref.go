package resource

import (
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
	"github.com/sufield/stave/internal/domain/asset"
)

// BuildBucketRefAsset creates an asset for an S3 bucket reference observation.
// The model is wrapped under the "s3_ref" property key, matching the field paths
// used by CTL.S3.BUCKET.TAKEOVER.001 (properties.s3_ref.bucket_exists, etc.).
func BuildBucketRefAsset(id asset.ID, model s3storage.S3BucketRefModel) asset.Asset {
	return asset.Asset{
		ID:     id,
		Type:   s3storage.TypeS3BucketRef,
		Vendor: s3storage.VendorAWS,
		Properties: map[string]any{
			"s3_ref": ToMap(model),
		},
	}
}
