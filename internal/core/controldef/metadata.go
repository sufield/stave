package controldef

import (
	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/kernel"
)

// ComplianceFramework identifies a compliance standard (e.g., "hipaa", "nist_800_53").
type ComplianceFramework string

// ComplianceMapping links compliance standards to specific control or requirement IDs.
type ComplianceMapping map[ComplianceFramework]string

// Get returns the requirement ID for a framework, or an empty string if not mapped.
func (m ComplianceMapping) Get(framework ComplianceFramework) string {
	if m == nil {
		return ""
	}
	return m[framework]
}

// Has reports whether the control is mapped to the given compliance standard.
func (m ComplianceMapping) Has(framework ComplianceFramework) bool {
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
