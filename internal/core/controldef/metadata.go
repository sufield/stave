package controldef

import (
	"errors"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/kernel"
)

// ComplianceFramework identifies a compliance standard (e.g., "hipaa", "nist_800_53").
type ComplianceFramework string

// RequirementID identifies a specific clause / control inside a
// compliance framework (e.g. "164.312(a)(1)", "SC-1"). Typed
// distinctly from kernel.ControlID so a compliance-mapping value
// cannot be silently passed to a function expecting a Stave control
// identifier — the two carry similar wire shapes but represent
// different things and a swap would be hard to debug.
type RequirementID string

// String returns the raw requirement string.
func (r RequirementID) String() string { return string(r) }

// IsEmpty reports whether the requirement is unset.
func (r RequirementID) IsEmpty() bool { return r == "" }

// ParseRequirementID returns a validated RequirementID. Trims
// surrounding whitespace and rejects the empty case so silently-blank
// compliance entries don't survive YAML loading.
func ParseRequirementID(raw string) (RequirementID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("requirement ID must not be empty")
	}
	return RequirementID(trimmed), nil
}

// ComplianceMapping links compliance standards to specific
// requirement IDs. The value type is RequirementID rather than a raw
// string so callers receive a typed identifier from Get() and cannot
// pass it to a function expecting a kernel.ControlID without an
// explicit conversion.
type ComplianceMapping map[ComplianceFramework]RequirementID

// Get returns the requirement ID for a framework, or an empty
// RequirementID if not mapped.
func (m ComplianceMapping) Get(framework ComplianceFramework) RequirementID {
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
