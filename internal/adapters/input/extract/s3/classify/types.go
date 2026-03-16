// Package classify translates S3-specific bucket policy, ACL, and website
// data into the vendor-neutral exposure domain model.
//
// The structs in this file are inbound DTOs: they capture raw data from
// external sources (AWS API, Terraform state) before the translator maps
// them into clean domain types.
package classify

// Bucket represents the raw S3 bucket configuration as ingested from
// an external source (e.g., a JSON snapshot or Terraform state).
type Bucket struct {
	Name              string  `json:"name"`
	Exists            bool    `json:"exists"`
	ExternalReference bool    `json:"external_reference"`
	Website           Website `json:"website"`
	Policy            Policy  `json:"policy"`
	ACL               ACL     `json:"acl"`
}

// Website represents the S3 static website hosting configuration.
type Website struct {
	Enabled bool `json:"enabled"`
}

// Policy represents a simplified AWS IAM policy document attached to a bucket.
type Policy struct {
	Statements []Statement `json:"statements"`
}

// Statement represents a single entry in an AWS IAM policy.
type Statement struct {
	Effect    string   `json:"effect"`
	Principal string   `json:"principal"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

// ACL represents the S3 Access Control List configuration.
type ACL struct {
	Grants []Grant `json:"grants"`
}

// Grant represents a single permission entry in an S3 ACL.
type Grant struct {
	Grantee    string `json:"grantee"`
	Permission string `json:"permission"`
	Scope      string `json:"scope,omitempty"`
}
