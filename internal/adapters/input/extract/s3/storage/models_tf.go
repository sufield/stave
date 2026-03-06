package storage

import s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"

// EncryptionConfig represents S3 server-side encryption configuration.
type EncryptionConfig struct {
	Algorithm string // "AES256" or "aws:kms"
	KMSKeyARN string // empty for AES256
}

// VersioningConfig represents S3 bucket versioning configuration.
type VersioningConfig struct {
	Status    string // "Enabled", "Suspended", or ""
	MFADelete string // "Enabled", "Disabled", or ""
}

// LoggingConfig represents S3 bucket logging configuration.
type LoggingConfig struct {
	TargetBucket string
	TargetPrefix string
}

// LifecycleConfig represents S3 bucket lifecycle configuration.
type LifecycleConfig struct {
	RulesConfigured                bool
	RuleCount                      int
	HasExpiration                  bool
	HasTransition                  bool
	MinExpirationDays              int
	HasNoncurrentVersionExpiration bool
}

// ObjectLockConfig represents S3 bucket object lock configuration.
type ObjectLockConfig struct {
	Enabled       bool
	Mode          string // "COMPLIANCE", "GOVERNANCE", or ""
	RetentionDays int
}

// WebsiteConfig represents S3 static website hosting configuration.
// Presence (non-nil pointer) means hosting is enabled.
type WebsiteConfig struct{}

// S3Bucket represents extracted S3 bucket information.
type S3Bucket struct {
	// Identity
	Name string
	ARN  string
	Tags map[string]string

	// Security data
	PolicyJSON        string
	ACLGrants         []s3acl.Grant
	PublicAccessBlock *PublicAccessBlock

	// Sub-configurations
	Encryption *EncryptionConfig
	Versioning *VersioningConfig
	Logging    *LoggingConfig
	Lifecycle  *LifecycleConfig
	ObjectLock *ObjectLockConfig
	Website    *WebsiteConfig
}

// PublicAccessBlock represents S3 public access block configuration.
type PublicAccessBlock struct {
	BlockPublicAcls       bool
	IgnorePublicAcls      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}
