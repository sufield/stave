package policy

import "github.com/sufield/stave/internal/domain/kernel"

// IAMManifestEntry is one extractor operation to IAM action mapping.
type IAMManifestEntry struct {
	Operation string `json:"operation"`
	Action    string `json:"action"`
}

// S3IngestIAMManifest is the source-of-truth least-privilege mapping for S3 ingest.
var S3IngestIAMManifest = []IAMManifestEntry{
	{Operation: "list-buckets", Action: "s3:ListAllMyBuckets"},
	{Operation: "get-bucket-tagging", Action: "s3:GetBucketTagging"},
	{Operation: "get-bucket-policy", Action: "s3:GetBucketPolicy"},
	{Operation: "get-bucket-acl", Action: "s3:GetBucketAcl"},
	{Operation: "get-public-access-block", Action: "s3:GetBucketPublicAccessBlock"},
}

// MinimumS3IngestIAMActions returns the normalized action allow-list.
// The canonical source of truth is kernel.DefaultPolicy().RequiredS3IAMActions.
func MinimumS3IngestIAMActions() []string {
	return kernel.DefaultPolicy().ProviderPermissions("aws")
}
