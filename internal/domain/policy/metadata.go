package policy

import "github.com/sufield/stave/internal/domain/kernel"

// ComplianceMapping maps compliance framework IDs to their control references.
// Keys are framework identifiers (e.g. "hipaa", "pci_dss"), values are control IDs.
type ComplianceMapping map[string]string

// Exposure classifies who can reach a resource and how.
// Not all findings involve exposure - only controls that detect
// accessibility violations carry exposure metadata.
type Exposure struct {
	// Type classifies the exposure condition
	// (e.g., "public_read", "acl_write", "bucket_takeover").
	Type string `json:"type" yaml:"type"`
	// PrincipalScope identifies who can exploit the exposure
	// (e.g., "public", "authenticated", "cross_account").
	PrincipalScope kernel.PrincipalScope `json:"principal_scope" yaml:"principal_scope"`
}
