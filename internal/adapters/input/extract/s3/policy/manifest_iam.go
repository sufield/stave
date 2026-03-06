package policy

import "sort"

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
func MinimumS3IngestIAMActions() []string {
	set := make(map[string]bool, len(S3IngestIAMManifest))
	for _, entry := range S3IngestIAMManifest {
		set[entry.Action] = true
	}
	out := make([]string, 0, len(set))
	for action := range set {
		out = append(out, action)
	}
	sort.Strings(out)
	return out
}
