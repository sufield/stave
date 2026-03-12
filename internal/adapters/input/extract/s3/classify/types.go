// Package classify translates S3-specific bucket policy, ACL, and website
// data into the vendor-neutral exposure domain model.
package classify

// S3BucketInput represents a bucket with raw S3 policy/ACL/website data.
type S3BucketInput struct {
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

// ACLGrant represents a single ACL grant.
type ACLGrant struct {
	Grantee    string `json:"grantee"`
	Permission string `json:"permission"`
	Scope      string `json:"scope,omitempty"`
}
