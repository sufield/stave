package policy

import "strings"

// RemediationSpec provides structured guidance on how to resolve a security violation.
// It is designed to be both human-readable and machine-parseable for automated ticketing or fix systems.
type RemediationSpec struct {
	// Description explains the security risk and the logic behind the required change.
	Description string `json:"description"`

	// Action describes the specific step needed to remediate the resource (e.g., a CLI command).
	Action string `json:"action"`

	// Example provides an optional concrete sample of the remediated state or command.
	Example string `json:"example,omitempty"`
}

// Actionable reports whether the specification contains a concrete remediation instruction.
// It is safe to call on a nil receiver.
func (s *RemediationSpec) Actionable() bool {
	return s != nil && strings.TrimSpace(s.Action) != ""
}

// IsValid reports whether the specification contains the minimum required
// information (Description and Action) to be useful to an operator.
func (s *RemediationSpec) IsValid() bool {
	if s == nil {
		return false
	}
	return strings.TrimSpace(s.Description) != "" && strings.TrimSpace(s.Action) != ""
}

// DeepCopy returns a new copy of the remediation specification.
func (s *RemediationSpec) DeepCopy() *RemediationSpec {
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}
