package storage

import (
	"github.com/sufield/stave/internal/domain/kernel"
	s3acl "github.com/sufield/stave/internal/domain/s3/acl"
)

// VersioningStatus represents the S3 bucket versioning state.
type VersioningStatus string

const (
	VersioningEnabled   VersioningStatus = "Enabled"
	VersioningSuspended VersioningStatus = "Suspended"
)

// MFADeleteStatus represents the S3 MFA delete state.
type MFADeleteStatus string

const (
	MFADeleteEnabled  MFADeleteStatus = "Enabled"
	MFADeleteDisabled MFADeleteStatus = "Disabled"
)

// ObjectLockMode represents the S3 object lock retention mode.
type ObjectLockMode string

const (
	ObjectLockCompliance ObjectLockMode = "COMPLIANCE"
	ObjectLockGovernance ObjectLockMode = "GOVERNANCE"
)

// EncryptionAlgorithm represents the S3 server-side encryption algorithm.
type EncryptionAlgorithm string

const (
	EncryptionAES256 EncryptionAlgorithm = "AES256"
	EncryptionAWSKMS EncryptionAlgorithm = "aws:kms"
)

// EncryptionConfig represents S3 server-side encryption configuration.
type EncryptionConfig struct {
	Algorithm EncryptionAlgorithm
	KMSKeyARN string // empty for AES256
}

// VersioningConfig represents S3 bucket versioning configuration.
type VersioningConfig struct {
	Status    VersioningStatus
	MFADelete MFADeleteStatus
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
	Mode          ObjectLockMode
	RetentionDays int
}

// WebsiteConfig represents S3 static website hosting configuration.
// Presence (non-nil pointer) means hosting is enabled.
type WebsiteConfig struct{}

// S3Bucket represents extracted S3 bucket information.
type S3Bucket struct {
	// Identity
	Name kernel.BucketRef
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
