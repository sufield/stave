package asset

import "time"

// S3BlockPublicAccess captures the four account/bucket-level Block Public Access
// settings that override individual bucket policies and ACLs.
type S3BlockPublicAccess struct {
	// BlockPublicACLs rejects PUT requests that include a public ACL.
	BlockPublicACLs bool `json:"block_public_acls"`

	// IgnorePublicACLs causes S3 to ignore all public ACLs on the bucket.
	IgnorePublicACLs bool `json:"ignore_public_acls"`

	// BlockPublicPolicy rejects bucket policy changes that would make the bucket public.
	BlockPublicPolicy bool `json:"block_public_policy"`

	// RestrictPublicBuckets restricts access to buckets with public policies
	// to only AWS service principals and authorized users.
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

// AllEnabled reports whether all four Block Public Access flags are true.
func (b S3BlockPublicAccess) AllEnabled() bool {
	return b.BlockPublicACLs && b.IgnorePublicACLs &&
		b.BlockPublicPolicy && b.RestrictPublicBuckets
}

// S3WebsiteConfig captures static website hosting configuration.
// A nil pointer in the parent means website hosting is not enabled.
type S3WebsiteConfig struct {
	// Enabled indicates whether static website hosting is turned on.
	Enabled bool `json:"enabled"`

	// IndexDocument is the default page served for directory requests (e.g. "index.html").
	IndexDocument *string `json:"index_document,omitempty"`

	// ErrorDocument is the custom error page (e.g. "error.html").
	ErrorDocument *string `json:"error_document,omitempty"`
}

// S3VPCEndpointPolicy captures a VPC endpoint policy document restricting
// access to the bucket through a specific VPC endpoint.
type S3VPCEndpointPolicy struct {
	// EndpointID is the VPC endpoint identifier (e.g. "vpce-1a2b3c4d").
	EndpointID string `json:"endpoint_id"`

	// PolicyJSON is the raw JSON policy document attached to the endpoint.
	PolicyJSON *string `json:"policy_json,omitempty"`

	// RestrictsAccess indicates whether the policy limits access beyond
	// the default allow-all.
	RestrictsAccess bool `json:"restricts_access"`
}

// S3BucketProperties provides typed access to S3-specific asset properties
// extracted from the observation property map.
type S3BucketProperties struct {
	// BucketName is the S3 bucket name.
	BucketName string `json:"bucket_name"`

	// CreatedAt is the bucket creation timestamp (ISO 8601).
	CreatedAt *time.Time `json:"created_at,omitempty"`

	// Tags is the bucket's key-value tag map.
	Tags map[string]string `json:"tags,omitempty"`

	// BlockPublicAccess holds the four Block Public Access flags.
	// Nil means the settings were not captured.
	BlockPublicAccess *S3BlockPublicAccess `json:"block_public_access,omitempty"`

	// Website holds static website hosting configuration.
	// Nil means website hosting is not enabled.
	Website *S3WebsiteConfig `json:"website,omitempty"`

	// VPCEndpointPolicy holds VPC endpoint policy details.
	// Nil means no VPC endpoint policy is associated.
	VPCEndpointPolicy *S3VPCEndpointPolicy `json:"vpc_endpoint_policy,omitempty"`
}
