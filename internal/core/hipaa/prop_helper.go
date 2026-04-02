package hipaa

import "github.com/sufield/stave/internal/core/asset"

// S3Properties provides typed access to S3 asset properties,
// replacing raw map[string]any traversal with compile-time safe fields.
// Missing or wrongly-typed values default to zero values (false, "").
type S3Properties struct {
	Encryption S3Encryption
	Versioning S3Versioning
	Access     S3Access
	Network    S3Network
	Logging    S3Logging
	ObjectLock S3ObjectLock
	Controls   S3Controls
	Ownership  string // "BucketOwnerEnforced", etc.
	PolicyJSON string // top-level policy_json
}

// S3Encryption holds encryption configuration.
type S3Encryption struct {
	AtRestEnabled  bool
	Algorithm      string
	KMSMasterKeyID string
}

// S3Versioning holds versioning configuration.
type S3Versioning struct {
	Enabled bool
}

// S3Access holds access condition flags.
type S3Access struct {
	HasVPCCondition bool
	HasIPCondition  bool
}

// S3Network holds network configuration.
type S3Network struct {
	VPCEndpointPolicy S3VPCEndpointPolicy
}

// S3VPCEndpointPolicy holds VPC endpoint policy state.
type S3VPCEndpointPolicy struct {
	Present             bool
	Attached            bool
	IsDefaultFullAccess bool
}

// S3Logging holds logging configuration.
type S3Logging struct {
	TargetBucket       string
	ObjectLevelLogging S3ObjectLevelLogging
}

// S3ObjectLevelLogging holds CloudTrail object-level logging state.
type S3ObjectLevelLogging struct {
	Present bool
	Enabled bool
}

// S3ObjectLock holds Object Lock configuration.
type S3ObjectLock struct {
	Present bool
	Enabled bool
	Mode    string
}

// S3Controls holds S3 control-plane settings.
type S3Controls struct {
	PublicAccessBlock               S3BlockPublicAccessConfig
	AccountPublicAccessFullyBlocked bool
}

// S3BlockPublicAccessConfig holds the four BPA flags.
type S3BlockPublicAccessConfig struct {
	Present               bool
	BlockPublicACLs       bool
	IgnorePublicACLs      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}

// AllEnabled reports whether all four BPA flags are true.
func (b S3BlockPublicAccessConfig) AllEnabled() bool {
	return b.BlockPublicACLs && b.IgnorePublicACLs && b.BlockPublicPolicy && b.RestrictPublicBuckets
}

// ParseS3Properties extracts typed S3 properties from an asset.
// Missing or wrongly-typed values produce zero-value fields.
func ParseS3Properties(a asset.Asset) S3Properties {
	var p S3Properties

	p.PolicyJSON, _ = a.Properties["policy_json"].(string)

	storage, _ := a.Properties["storage"].(map[string]any)
	if storage == nil {
		return p
	}

	p.Ownership, _ = storage["ownership_controls"].(string)

	// Encryption
	if enc, _ := storage["encryption"].(map[string]any); enc != nil {
		p.Encryption.AtRestEnabled, _ = enc["at_rest_enabled"].(bool)
		p.Encryption.Algorithm, _ = enc["algorithm"].(string)
		p.Encryption.KMSMasterKeyID, _ = enc["kms_master_key_id"].(string)
	}

	// Versioning
	if ver, _ := storage["versioning"].(map[string]any); ver != nil {
		p.Versioning.Enabled, _ = ver["enabled"].(bool)
	}

	// Access
	if acc, _ := storage["access"].(map[string]any); acc != nil {
		p.Access.HasVPCCondition, _ = acc["has_vpc_condition"].(bool)
		p.Access.HasIPCondition, _ = acc["has_ip_condition"].(bool)
	}

	// Network
	if net, _ := storage["network"].(map[string]any); net != nil {
		if vep, _ := net["vpc_endpoint_policy"].(map[string]any); vep != nil {
			p.Network.VPCEndpointPolicy.Present = true
			p.Network.VPCEndpointPolicy.Attached, _ = vep["attached"].(bool)
			p.Network.VPCEndpointPolicy.IsDefaultFullAccess, _ = vep["is_default_full_access"].(bool)
		}
	}

	// Logging
	if log, _ := storage["logging"].(map[string]any); log != nil {
		p.Logging.TargetBucket, _ = log["target_bucket"].(string)
		if obj, _ := log["object_level_logging"].(map[string]any); obj != nil {
			p.Logging.ObjectLevelLogging.Present = true
			p.Logging.ObjectLevelLogging.Enabled, _ = obj["enabled"].(bool)
		}
	}

	// Object Lock
	if lock, _ := storage["object_lock"].(map[string]any); lock != nil {
		p.ObjectLock.Present = true
		p.ObjectLock.Enabled, _ = lock["enabled"].(bool)
		p.ObjectLock.Mode, _ = lock["mode"].(string)
	}

	// Controls (BPA)
	if ctl, _ := storage["controls"].(map[string]any); ctl != nil {
		p.Controls.AccountPublicAccessFullyBlocked, _ = ctl["account_public_access_fully_blocked"].(bool)
		if block, _ := ctl["public_access_block"].(map[string]any); block != nil {
			p.Controls.PublicAccessBlock.Present = true
			p.Controls.PublicAccessBlock.BlockPublicACLs, _ = block["block_public_acls"].(bool)
			p.Controls.PublicAccessBlock.IgnorePublicACLs, _ = block["ignore_public_acls"].(bool)
			p.Controls.PublicAccessBlock.BlockPublicPolicy, _ = block["block_public_policy"].(bool)
			p.Controls.PublicAccessBlock.RestrictPublicBuckets, _ = block["restrict_public_buckets"].(bool)
		}
	}

	return p
}

// isS3Bucket reports whether the asset is an S3 bucket.
func isS3Bucket(a asset.Asset) bool {
	return a.Type.String() == "aws_s3_bucket"
}
