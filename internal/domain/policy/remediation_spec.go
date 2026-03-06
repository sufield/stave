package policy

// RemediationSpec defines static, machine-readable fix guidance for an control.
type RemediationSpec struct {
	Description string `json:"description" yaml:"description"`
	Action      string `json:"action" yaml:"action"`
	Example     string `json:"example,omitempty" yaml:"example,omitempty"`
}

// Actionable reports whether the spec has a concrete remediation action.
// Nil-safe: returns false for a nil receiver.
func (r *RemediationSpec) Actionable() bool {
	return r != nil && r.Action != ""
}
