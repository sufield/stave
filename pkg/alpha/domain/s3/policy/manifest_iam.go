package policy

import "github.com/sufield/stave/pkg/alpha/domain/kernel"

// IAMManifestEntry is one extractor operation to IAM action mapping.
type IAMManifestEntry struct {
	Operation string `json:"operation"`
	Action    string `json:"action"`
}

// S3IngestIAMManifest is the source-of-truth least-privilege mapping for S3 observation collection.
var S3IngestIAMManifest = []IAMManifestEntry{
	{Operation: "aws s3api list-buckets", Action: "s3:ListAllMyBuckets"},
	{Operation: "aws s3api get-bucket-tagging", Action: "s3:GetBucketTagging"},
	{Operation: "aws s3api get-bucket-policy", Action: "s3:GetBucketPolicy"},
	{Operation: "aws s3api get-bucket-acl", Action: "s3:GetBucketAcl"},
	{Operation: "aws s3api get-public-access-block", Action: "s3:GetBucketPublicAccessBlock"},
	{Operation: "aws s3api get-bucket-encryption", Action: "s3:GetEncryptionConfiguration"},
	{Operation: "aws s3api get-bucket-versioning", Action: "s3:GetBucketVersioning"},
	{Operation: "aws s3api get-object-lock-configuration", Action: "s3:GetBucketObjectLockConfiguration"},
	{Operation: "aws s3api get-bucket-logging", Action: "s3:GetBucketLogging"},
	{Operation: "aws s3api get-bucket-lifecycle-configuration", Action: "s3:GetLifecycleConfiguration"},
}

// MinimumS3IngestIAMActions returns the normalized action allow-list.
// The canonical source of truth is kernel.DefaultPolicy().RequiredS3IAMActions.
func MinimumS3IngestIAMActions() []string {
	return kernel.DefaultPolicy().ProviderPermissions("aws")
}
