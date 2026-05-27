package main

// s3GetActions enumerates a representative subset of S3
// actions whose name starts with "s3:Get". Source:
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html
//
// The list is intentionally short of every Get action S3
// supports — the demo only needs enough variety to show that
// `s3:Get*` admits actions far beyond what replication
// requires. Each action in the list is a real S3 API name.
var s3GetActions = []string{
	"s3:GetBucketAcl",
	"s3:GetBucketCORS",
	"s3:GetBucketEncryptionConfiguration",
	"s3:GetBucketLifecycleConfiguration",
	"s3:GetBucketLocation",
	"s3:GetBucketLogging",
	"s3:GetBucketNotification",
	"s3:GetBucketObjectLockConfiguration",
	"s3:GetBucketPolicy",
	"s3:GetBucketPolicyStatus",
	"s3:GetBucketPublicAccessBlock",
	"s3:GetBucketTagging",
	"s3:GetBucketVersioning",
	"s3:GetBucketWebsite",
	"s3:GetEncryptionConfiguration",
	"s3:GetIntelligentTieringConfiguration",
	"s3:GetInventoryConfiguration",
	"s3:GetLifecycleConfiguration",
	"s3:GetMetricsConfiguration",
	"s3:GetObject",
	"s3:GetObjectAcl",
	"s3:GetObjectLegalHold",
	"s3:GetObjectRetention",
	"s3:GetObjectTagging",
	"s3:GetObjectTorrent",
	"s3:GetObjectVersion",
	"s3:GetObjectVersionAcl",
	"s3:GetObjectVersionForReplication",
	"s3:GetObjectVersionTagging",
	"s3:GetObjectVersionTorrent",
	"s3:GetReplicationConfiguration",
}

// replicationRequiredOnDestination is the set of `s3:Get*` /
// `s3:Put*` / `s3:Replicate*` actions S3's cross-region
// replication actually needs on the destination bucket.
//
// Source: AWS docs on S3 replication required permissions.
// The destination policy needs ReplicateObject + ReplicateDelete
// + ObjectOwnerOverrideToBucketOwner; the only `Get` action it
// needs is GetBucketVersioning to verify versioning is on.
var replicationRequiredOnDestination = map[string]bool{
	"s3:GetBucketVersioning":              true,
	"s3:PutBucketVersioning":              true,
	"s3:ReplicateObject":                  true,
	"s3:ReplicateDelete":                  true,
	"s3:ObjectOwnerOverrideToBucketOwner": true,
}

// excessGetActions returns the s3:Get* actions whose names
// match the s3:Get* wildcard pattern but which replication
// does not actually require. These are the witnesses Z3
// enumerates to demonstrate that `s3:Get*` admits more than
// the policy author intended.
func excessGetActions() []string {
	out := []string{}
	for _, a := range s3GetActions {
		if !replicationRequiredOnDestination[a] {
			out = append(out, a)
		}
	}
	return out
}
