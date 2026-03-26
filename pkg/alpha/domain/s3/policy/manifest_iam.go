package policy

import "github.com/sufield/stave/pkg/alpha/domain/kernel"

// PermissionMapping links a CLI/API operation to its required IAM action.
// Used for documentation generation and least-privilege validation.
type PermissionMapping struct {
	Operation string `json:"operation"` // e.g., "aws s3api list-buckets"
	Action    string `json:"action"`    // e.g., "s3:ListAllMyBuckets"
}

// S3IngestPermissions is the source-of-truth least-privilege mapping for
// S3 observation collection. Each entry pairs a CLI operation with the
// IAM action it requires.
var S3IngestPermissions = []PermissionMapping{
	{"aws s3api list-buckets", "s3:ListAllMyBuckets"},
	{"aws s3api get-bucket-tagging", "s3:GetBucketTagging"},
	{"aws s3api get-bucket-policy", "s3:GetBucketPolicy"},
	{"aws s3api get-bucket-acl", "s3:GetBucketAcl"},
	{"aws s3api get-public-access-block", "s3:GetBucketPublicAccessBlock"},
	{"aws s3api get-bucket-encryption", "s3:GetEncryptionConfiguration"},
	{"aws s3api get-bucket-versioning", "s3:GetBucketVersioning"},
	{"aws s3api get-object-lock-configuration", "s3:GetBucketObjectLockConfiguration"},
	{"aws s3api get-bucket-logging", "s3:GetBucketLogging"},
	{"aws s3api get-bucket-lifecycle-configuration", "s3:GetLifecycleConfiguration"},
}

// MinimumS3IngestIAMActions returns the normalized action allow-list
// from the kernel's default provider policy.
func MinimumS3IngestIAMActions() []string {
	return kernel.DefaultPolicy().ProviderPermissions("aws")
}
