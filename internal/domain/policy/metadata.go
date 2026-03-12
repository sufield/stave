package policy

import "github.com/sufield/stave/internal/domain/kernel"

// ComplianceMapping associates compliance framework identifiers (e.g., "hipaa", "nist_800_53")
// with specific control or requirement indices.
type ComplianceMapping map[string]string

// Get returns the requirement ID for a specific framework, or an empty string if not mapped.
func (cm ComplianceMapping) Get(framework string) string {
	if cm == nil {
		return ""
	}
	return cm[framework]
}

// HasFramework reports whether the control is mapped to the given compliance standard.
func (cm ComplianceMapping) HasFramework(framework string) bool {
	return cm.Get(framework) != ""
}

// Exposure describes the accessibility risk associated with a control violation.
// This metadata is only present on controls that detect visibility or reachability issues.
type Exposure struct {
	// Type classifies the specific risk (e.g., "public_read", "public_write", "resource_takeover").
	Type string `json:"type" yaml:"type"`

	// PrincipalScope defines the reachability boundary (e.g., "public", "authenticated").
	PrincipalScope kernel.PrincipalScope `json:"principal_scope" yaml:"principal_scope"`
}

// IsPublic returns true if the exposure allows anonymous or unauthenticated access.
func (e *Exposure) IsPublic() bool {
	if e == nil {
		return false
	}
	return e.PrincipalScope.IsPublic()
}

// IsValid checks if the exposure metadata contains the required fields.
func (e *Exposure) IsValid() bool {
	return e != nil && e.Type != "" && e.PrincipalScope.IsValid()
}
