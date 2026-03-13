package terraform

import s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"

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

// Bucket is the normalized Terraform-collected bucket state.
type Bucket struct {
	// Identity
	Name string
	ARN  string
	Tags map[string]string

	// Security data
	PolicyJSON        string
	ACLGrants         []ACLGrant
	PublicAccessBlock *s3storage.PublicAccessBlock

	// Sub-configurations
	Encryption *s3storage.EncryptionConfig
	Versioning *s3storage.VersioningConfig
	Logging    *s3storage.LoggingConfig
	Lifecycle  *s3storage.LifecycleConfig
	ObjectLock *s3storage.ObjectLockConfig
	Website    *s3storage.WebsiteConfig
}
