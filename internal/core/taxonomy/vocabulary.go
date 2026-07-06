package taxonomy

import "github.com/sufield/stave/internal/core/kernel"

// Category holds the rich metadata for a taxonomy category.
type Category struct {
	ID         kernel.CategoryID `json:"id"`
	Name       string            `json:"name"`
	Definition string            `json:"definition"`
	Examples   []string          `json:"examples"`
}

// Vocabulary returns all taxonomy categories with human-readable metadata.
func Vocabulary() []Category {
	return []Category{
		{
			ID:         LeastPrivilege,
			Name:       "Least Privilege",
			Definition: "Controls that detect permissions broader than necessary.",
			Examples:   []string{"IAM policy with Action:* Resource:*"},
		},
		{
			ID:         CredentialLifecycle,
			Name:       "Credential Lifecycle",
			Definition: "Controls that detect credentials that outlive their need.",
			Examples:   []string{"IAM access key older than 90 days"},
		},
		{
			ID:         TrustBoundary,
			Name:       "Trust Boundary",
			Definition: "Controls that detect cross-account trust without external ID.",
			Examples:   []string{"Role trust policy with wildcard principal"},
		},
		{
			ID:         TrustDecay,
			Name:       "Trust Decay",
			Definition: "Controls that detect stale, idle, or orphaned resources.",
			Examples:   []string{"Security group with no attached ENIs for 30 days"},
		},
		{
			ID:         ConfusedDeputy,
			Name:       "Confused Deputy",
			Definition: "Controls that detect missing source-account conditions in trust policies.",
			Examples:   []string{"Role assumable without aws:SourceAccount condition"},
		},
		{
			ID:         Attribution,
			Name:       "Attribution",
			Definition: "Controls that detect gaps in identity and action logging.",
			Examples:   []string{"CloudTrail not enabled in all regions"},
		},
		{
			ID:         IdentityPerimeter,
			Name:       "Identity Perimeter",
			Definition: "Controls that detect access from outside the organization.",
			Examples:   []string{"S3 bucket policy missing aws:PrincipalOrgID condition"},
		},
		{
			ID:         Impersonation,
			Name:       "Impersonation",
			Definition: "Controls that detect unauthorized identity assumption.",
			Examples:   []string{"SSO OAuth token issuance without MFA"},
		},
		{
			ID:         NetworkPerimeter,
			Name:       "Network Perimeter",
			Definition: "Controls that detect unrestricted network ingress.",
			Examples:   []string{"Security group allowing 0.0.0.0/0 on port 22"},
		},
		{
			ID:         DataPerimeter,
			Name:       "Data Perimeter",
			Definition: "Controls that detect missing organization-scoped data access conditions.",
			Examples:   []string{"S3 bucket policy without aws:PrincipalOrgID"},
		},
		{
			ID:         EncryptionAtRest,
			Name:       "Encryption at Rest",
			Definition: "Controls that detect unencrypted stored data.",
			Examples:   []string{"EBS volume without encryption enabled"},
		},
		{
			ID:         EncryptionInTransit,
			Name:       "Encryption in Transit",
			Definition: "Controls that detect unencrypted data in motion.",
			Examples:   []string{"Load balancer listener using HTTP instead of HTTPS"},
		},
		{
			ID:         KeyManagement,
			Name:       "Key Management",
			Definition: "Controls that detect misconfigured encryption key policies.",
			Examples:   []string{"KMS key without automatic rotation enabled"},
		},
		{
			ID:         NetworkIsolation,
			Name:       "Network Isolation",
			Definition: "Controls that detect resources outside VPC isolation.",
			Examples:   []string{"Lambda function not attached to a VPC"},
		},
		{
			ID:         ComputeHardening,
			Name:       "Compute Hardening",
			Definition: "Controls that detect insecure compute configurations.",
			Examples:   []string{"EC2 instance using IMDSv1 instead of IMDSv2"},
		},
		{
			ID:         Redundancy,
			Name:       "Redundancy & Availability",
			Definition: "Controls that detect single points of failure.",
			Examples:   []string{"RDS instance without Multi-AZ enabled"},
		},
		{
			ID:         Logging,
			Name:       "Logging & Audit",
			Definition: "Controls that detect disabled or incomplete audit trails.",
			Examples:   []string{"S3 bucket without access logging"},
		},
		{
			ID:         Monitoring,
			Name:       "Monitoring & Detection",
			Definition: "Controls that detect gaps in security monitoring.",
			Examples:   []string{"GuardDuty not enabled in the account"},
		},
		{
			ID:         AIGuardrails,
			Name:       "AI Guardrails",
			Definition: "Controls that detect missing content safety filters on AI services.",
			Examples:   []string{"Bedrock guardrail without PII filter"},
		},
		{
			ID:         AISupplyChain,
			Name:       "AI Supply Chain",
			Definition: "Controls that detect unscanned or untrusted AI model artifacts.",
			Examples:   []string{"ECR repository without scan-on-push enabled"},
		},
		{
			ID:         ResourceSprawl,
			Name:       "Resource Sprawl",
			Definition: "Controls that detect shadow or unmanaged resources.",
			Examples:   []string{"Unattached EBS volume with no tags"},
		},
		{
			ID:         AccountGovernance,
			Name:       "Account Governance",
			Definition: "Controls that detect missing organization-level policies.",
			Examples:   []string{"Account without SCP guardrails"},
		},
		{
			ID:         ComplianceMapping,
			Name:       "Compliance Mapping",
			Definition: "Controls mapped to regulatory frameworks.",
			Examples:   []string{"Control mapped to CIS Benchmark 1.4"},
		},
		{
			ID:         FormalSemantics,
			Name:       "Policy Evaluation Semantics",
			Definition: "Controls that detect IAM condition key misuse.",
			Examples:   []string{"ForAllValues on a single-valued condition key"},
		},
		{
			ID:         DetectionEvasion,
			Name:       "Detection Evasion",
			Definition: "Controls that detect weakened detection infrastructure.",
			Examples:   []string{"WAF IP set with zero addresses"},
		},
		{
			ID:         Deprecation,
			Name:       "Deprecation & Lifecycle",
			Definition: "Controls that detect end-of-life or deprecated resources.",
			Examples:   []string{"Lambda function using a deprecated runtime"},
		},
		{
			ID:         DataProtection,
			Name:       "Data Protection",
			Definition: "Controls that detect missing deletion protection or backup.",
			Examples:   []string{"RDS instance without deletion protection"},
		},
	}
}

// LookupCategory returns the Category for a given ID.
func LookupCategory(id kernel.CategoryID) (Category, bool) {
	for _, c := range Vocabulary() {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// CategoryName returns the human-readable name for a category ID,
// or the raw ID string if not found in the vocabulary.
func CategoryName(id kernel.CategoryID) string {
	if c, ok := LookupCategory(id); ok {
		return c.Name
	}
	return string(id)
}
