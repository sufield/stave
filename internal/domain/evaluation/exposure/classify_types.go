package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// ExposureBucketInput represents a bucket with raw policy/ACL/website data.
type ExposureBucketInput struct {
	Name              string        `json:"name"`
	Exists            bool          `json:"exists"`
	ExternalReference bool          `json:"external_reference"`
	Website           WebsiteConfig `json:"website"`
	Policy            PolicyConfig  `json:"policy"`
	ACL               ACLConfig     `json:"acl"`
}

// WebsiteConfig represents S3 static website hosting configuration.
type WebsiteConfig struct {
	Enabled bool `json:"enabled"`
}

// PolicyConfig represents a simplified bucket policy.
type PolicyConfig struct {
	Statements []StatementInput `json:"statements"`
}

// StatementInput represents a single policy statement.
type StatementInput struct {
	Effect    string   `json:"effect"`
	Principal string   `json:"principal"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

// ACLConfig represents simplified ACL grants.
type ACLConfig struct {
	Grants []ACLGrant `json:"grants"`
}

// ACLGrant represents a single ACL grant used by exposure analysis.
type ACLGrant struct {
	Grantee    string `json:"grantee"`
	Permission string `json:"permission"`
	Scope      string `json:"scope,omitempty"`
}

// ExposureClassification represents a classified exposure vector for a bucket.
type ExposureClassification struct {
	ID             kernel.ControlID      `json:"id"`
	Bucket         string                `json:"bucket"`
	ExposureType   string                `json:"exposure_type"`
	PrincipalScope kernel.PrincipalScope `json:"principal_scope"`
	Actions        []string              `json:"actions"`
	WriteScope     string                `json:"write_scope,omitempty"`
	EvidencePath   []string              `json:"evidence_path"`
}

// Classifications wraps a slice of classifications for JSON serialization.
type Classifications struct {
	Classifications []ExposureClassification `json:"findings"`
}
