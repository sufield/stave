// Package taxonomy defines the ubiquitous vocabulary for security
// concept categories. Go constants are the source of truth;
// data/taxonomy.yaml is a serialization.
package taxonomy

import "github.com/sufield/stave/internal/core/kernel"

const (
	LeastPrivilege      kernel.CategoryID = "least-privilege"
	CredentialLifecycle kernel.CategoryID = "credential-lifecycle" //nolint:gosec // taxonomy category name, not a credential
	TrustBoundary       kernel.CategoryID = "trust-boundary"
	TrustDecay          kernel.CategoryID = "trust-decay"
	ConfusedDeputy      kernel.CategoryID = "confused-deputy"
	Attribution         kernel.CategoryID = "attribution"
	IdentityPerimeter   kernel.CategoryID = "identity-perimeter"
	Impersonation       kernel.CategoryID = "impersonation"
	NetworkPerimeter    kernel.CategoryID = "network-perimeter"
	DataPerimeter       kernel.CategoryID = "data-perimeter"
	EncryptionAtRest    kernel.CategoryID = "encryption-at-rest"
	EncryptionInTransit kernel.CategoryID = "encryption-in-transit"
	KeyManagement       kernel.CategoryID = "key-management"
	NetworkIsolation    kernel.CategoryID = "network-isolation"
	ComputeHardening    kernel.CategoryID = "compute-hardening"
	Redundancy          kernel.CategoryID = "redundancy"
	Logging             kernel.CategoryID = "logging"
	Monitoring          kernel.CategoryID = "monitoring"
	AIGuardrails        kernel.CategoryID = "ai-guardrails"
	AISupplyChain       kernel.CategoryID = "ai-supply-chain"
	ResourceSprawl      kernel.CategoryID = "resource-sprawl"
	AccountGovernance   kernel.CategoryID = "account-governance"
	ComplianceMapping   kernel.CategoryID = "compliance-mapping"
	FormalSemantics     kernel.CategoryID = "formal-semantics"
	DetectionEvasion    kernel.CategoryID = "detection-evasion"
	Deprecation         kernel.CategoryID = "deprecation"
	DataProtection      kernel.CategoryID = "data-protection"
)

// All is the canonical ordered list of every taxonomy category.
var All = []kernel.CategoryID{
	LeastPrivilege,
	CredentialLifecycle,
	TrustBoundary,
	TrustDecay,
	ConfusedDeputy,
	Attribution,
	IdentityPerimeter,
	Impersonation,
	NetworkPerimeter,
	DataPerimeter,
	EncryptionAtRest,
	EncryptionInTransit,
	KeyManagement,
	NetworkIsolation,
	ComputeHardening,
	Redundancy,
	Logging,
	Monitoring,
	AIGuardrails,
	AISupplyChain,
	ResourceSprawl,
	AccountGovernance,
	ComplianceMapping,
	FormalSemantics,
	DetectionEvasion,
	Deprecation,
	DataProtection,
}

func init() {
	ids := make([]string, len(All))
	for i, c := range All {
		ids[i] = string(c)
	}
	kernel.SetCategoryIDVocabulary(ids)
}
