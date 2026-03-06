package terraform

const (
	tfTypeS3Bucket                        = "aws_s3_bucket"
	tfTypeS3BucketPolicy                  = "aws_s3_bucket_policy"
	tfTypeS3BucketACL                     = "aws_s3_bucket_acl"
	tfTypeS3BucketPublicAccessBlock       = "aws_s3_bucket_public_access_block"
	tfTypeS3AccountPublicAccessBlock      = "aws_s3_account_public_access_block"
	tfTypeS3BucketSSEConfiguration        = "aws_s3_bucket_server_side_encryption_configuration"
	tfTypeS3BucketVersioning              = "aws_s3_bucket_versioning"
	tfTypeS3BucketLogging                 = "aws_s3_bucket_logging"
	tfTypeS3BucketLifecycleConfiguration  = "aws_s3_bucket_lifecycle_configuration"
	tfTypeS3BucketObjectLockConfiguration = "aws_s3_bucket_object_lock_configuration"
	tfTypeS3BucketWebsiteConfiguration    = "aws_s3_bucket_website_configuration"
)

type resourceHandler func(resName string, values map[string]any, state *State)

var s3ResourceHandlers = map[string]resourceHandler{
	tfTypeS3Bucket:                        handleS3BucketResource,
	tfTypeS3BucketPolicy:                  handleS3BucketPolicyResource,
	tfTypeS3BucketACL:                     handleS3BucketACLResource,
	tfTypeS3BucketPublicAccessBlock:       handleS3BucketPublicAccessBlockResource,
	tfTypeS3AccountPublicAccessBlock:      handleS3AccountPublicAccessBlockResource,
	tfTypeS3BucketSSEConfiguration:        handleS3BucketSSEConfigurationResource,
	tfTypeS3BucketVersioning:              handleS3BucketVersioningResource,
	tfTypeS3BucketLogging:                 handleS3BucketLoggingResource,
	tfTypeS3BucketLifecycleConfiguration:  handleS3BucketLifecycleConfigurationResource,
	tfTypeS3BucketObjectLockConfiguration: handleS3BucketObjectLockConfigurationResource,
	tfTypeS3BucketWebsiteConfiguration:    handleS3BucketWebsiteConfigurationResource,
}

// CollectResource merges a Terraform resource into the mutable collection state.
func CollectResource(resType, resName string, values map[string]any, state *State) {
	handler, ok := s3ResourceHandlers[resType]
	if !ok {
		return
	}
	handler(resName, values, state)
}

func handleS3BucketResource(resName string, values map[string]any, state *State) {
	p := newMapPicker(values)
	name := getBucketName(resName, p)
	bucket := &Bucket{
		Name: name,
		ARN:  p.String("arn"),
		Tags: p.StringMap("tags"),
	}
	// object_lock_enabled may be set on the bucket itself.
	if p.String("object_lock_enabled") == "Enabled" {
		state.SetObjectLock(name, &ObjectLockConfig{Enabled: true})
	}
	state.Buckets[name] = bucket
}

func handleS3BucketPolicyResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	state.Policies[bucketName] = p.String("policy")
}

func handleS3BucketACLResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	state.ACLs[bucketName] = extractACLGrants(values)
}

func handleS3BucketPublicAccessBlockResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	state.PABs[bucketName] = &PublicAccessBlock{
		BlockPublicAcls:       p.Bool("block_public_acls"),
		IgnorePublicAcls:      p.Bool("ignore_public_acls"),
		BlockPublicPolicy:     p.Bool("block_public_policy"),
		RestrictPublicBuckets: p.Bool("restrict_public_buckets"),
	}
}

func handleS3AccountPublicAccessBlockResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	state.AccountPAB = &PublicAccessBlock{
		BlockPublicAcls:       p.Bool("block_public_acls"),
		IgnorePublicAcls:      p.Bool("ignore_public_acls"),
		BlockPublicPolicy:     p.Bool("block_public_policy"),
		RestrictPublicBuckets: p.Bool("restrict_public_buckets"),
	}
}

func handleS3BucketSSEConfigurationResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	state.Encryptions[bucketName] = extractEncryptionConfig(values)
}

func handleS3BucketVersioningResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	state.Versionings[bucketName] = extractVersioningConfig(values)
}

func handleS3BucketLoggingResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	state.Loggings[bucketName] = extractLoggingConfig(values)
}

func handleS3BucketLifecycleConfigurationResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	state.Lifecycles[bucketName] = extractLifecycleConfig(values)
}

func handleS3BucketObjectLockConfigurationResource(resName string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := getBucketName(resName, p)
	if bucketName == "" {
		return
	}
	olc := extractObjectLockConfig(values)
	olc.Enabled = true
	state.SetObjectLock(bucketName, olc)
}

func handleS3BucketWebsiteConfigurationResource(_ string, values map[string]any, state *State) {
	p := newMapPicker(values)
	bucketName := p.String("bucket")
	if bucketName == "" {
		return
	}
	if b, ok := state.Buckets[bucketName]; ok {
		b.Website = &WebsiteConfig{}
	}
}
