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

// NewRemediationSpec constructs a spec with whitespace-trimmed Description and Action.
// Example is left as-is because it may contain multiline block content.
// Use this at input boundaries (YAML loading, API ingestion) to normalize
// data before it enters the domain.
func NewRemediationSpec(desc, action, example string) *RemediationSpec {
	return &RemediationSpec{
		Description: strings.TrimSpace(desc),
		Action:      strings.TrimSpace(action),
		Example:     example,
	}
}

// Actionable reports whether the specification contains a concrete remediation instruction.
// It is safe to call on a nil receiver.
func (s *RemediationSpec) Actionable() bool {
	return s != nil && s.Action != ""
}
