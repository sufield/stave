package kernel

// Identity type aliases for domain concepts that are used as identifiers
// across the codebase. These are pure value types with no behavior — if
// validation or parsing is needed, they graduate to their own file.

// AssetDomain identifies the domain segment of a control or asset type (e.g., "s3", "iam").
type AssetDomain string

// PackName is a typed string identifying a control pack
// (e.g., "s3/public", "hipaa", "cis-aws-v1").
type PackName string

// ScopeTag is a typed string identifying a scope or classification tag
// on a control definition (e.g., "aws", "s3", "compliance").
type ScopeTag string

// AWSAccountID is a 12-digit AWS account identifier.
type AWSAccountID string

// AWSAccountARN is a full AWS IAM ARN (e.g., "arn:aws:iam::123456789012:root").
type AWSAccountARN string
