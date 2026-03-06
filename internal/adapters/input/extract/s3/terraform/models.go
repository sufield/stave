package terraform

const (
	permRead  = "READ"
	permWrite = "WRITE"
)

// AllUsersGranteeURI is the AWS public ACL grantee token.
const AllUsersGranteeURI = "http://acs.amazonaws.com/groups/global/AllUsers"

// AuthenticatedUsersGranteeURI is the AWS authenticated-users ACL grantee token.
const AuthenticatedUsersGranteeURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

// Plan represents the structure of terraform show -json output.
type Plan struct {
	PlannedValues struct {
		RootModule struct {
			Resources []Resource `json:"resources"`
		} `json:"root_module"`
	} `json:"planned_values"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
}

// Resource represents a resource in the plan.
type Resource struct {
	Address string         `json:"address"`
	Type    string         `json:"type"`
	Name    string         `json:"name"`
	Values  map[string]any `json:"values"`
}

// ResourceChange represents a resource change in the plan.
type ResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Change  struct {
		After map[string]any `json:"after"`
	} `json:"change"`
}

// ACLGrant represents one extracted ACL grant.
type ACLGrant struct {
	Grantee    string
	Permission string
}

// EncryptionConfig represents S3 SSE configuration.
type EncryptionConfig struct {
	Algorithm string
	KMSKeyARN string
}

// VersioningConfig represents S3 bucket versioning configuration.
type VersioningConfig struct {
	Status    string
	MFADelete string
}

// LoggingConfig represents S3 bucket logging configuration.
type LoggingConfig struct {
	TargetBucket string
	TargetPrefix string
}

// LifecycleConfig represents S3 lifecycle configuration.
type LifecycleConfig struct {
	RulesConfigured                bool
	RuleCount                      int
	HasExpiration                  bool
	HasTransition                  bool
	MinExpirationDays              int
	HasNoncurrentVersionExpiration bool
}

// ObjectLockConfig represents S3 object lock configuration.
type ObjectLockConfig struct {
	Enabled       bool
	Mode          string
	RetentionDays int
}

// WebsiteConfig represents S3 static website hosting configuration.
// Presence (non-nil pointer) means hosting is enabled.
type WebsiteConfig struct{}

// Bucket is the normalized Terraform-collected bucket state.
type Bucket struct {
	// Identity
	Name string
	ARN  string
	Tags map[string]string

	// Security data
	PolicyJSON        string
	ACLGrants         []ACLGrant
	PublicAccessBlock *PublicAccessBlock

	// Sub-configurations
	Encryption *EncryptionConfig
	Versioning *VersioningConfig
	Logging    *LoggingConfig
	Lifecycle  *LifecycleConfig
	ObjectLock *ObjectLockConfig
	Website    *WebsiteConfig
}

// PublicAccessBlock represents S3 public access block settings.
type PublicAccessBlock struct {
	BlockPublicAcls       bool
	IgnorePublicAcls      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}
