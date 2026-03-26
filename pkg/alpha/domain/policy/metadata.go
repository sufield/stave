package policy

import (
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/exposure"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// ComplianceMapping links compliance standards (e.g., "hipaa", "nist_800_53")
// to specific control or requirement IDs.
type ComplianceMapping map[string]string

// Get returns the requirement ID for a framework, or an empty string if not mapped.
func (m ComplianceMapping) Get(framework string) string {
	if m == nil {
		return ""
	}
	return m[framework]
}

// Has reports whether the control is mapped to the given compliance standard.
// Uses the comma-ok idiom to distinguish missing keys from empty values.
func (m ComplianceMapping) Has(framework string) bool {
	if m == nil {
		return false
	}
	_, ok := m[framework]
	return ok
}

// Exposure describes the accessibility risk associated with a control violation.
// This metadata is only present on controls that detect visibility or reachability issues.
type Exposure struct {
	// Type classifies the specific risk (e.g., "public_read", "resource_takeover").
	Type exposure.Type `json:"type" yaml:"type"`

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
