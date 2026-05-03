package controldef

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

	// Confidence indicates how certain Stave is that the suggested changes
	// resolve the finding. Range 0.0–1.0. Populated from ConfidenceLevel.
	Confidence float64 `json:"confidence,omitempty"`

	// RiskScore is the environmental exposure score if available.
	RiskScore *float64 `json:"risk_score,omitempty"`

	// Changes provides machine-readable, IaC-agnostic property changes
	// derived from the finding's misconfigurations.
	Changes []PropertyChange `json:"changes,omitempty"`

	// RequiredValuePrompt is a natural-language question a downstream
	// consumer (AI prompt, ticket system, human) can use to elicit the
	// correct value from the user when HasSafeDefault is false. Empty
	// means the control author didn't provide a prompt — downstream
	// consumers handle absence by asking the user directly. See
	// docs/product/metrics.md § Metric 4.
	RequiredValuePrompt string `json:"required_value_prompt,omitempty" yaml:"required_value_prompt"`

	// FindingID is the stable fingerprint for the (control, asset) pair.
	// Copied from Finding.FindingID at construction — not recomputed.
	FindingID string `json:"finding_id,omitempty"`
}

// PropertyChange is a single structured property change.
// It is IaC-tool-agnostic — any tool can consume it.
type PropertyChange struct {
	// PropertyPath is the observation property path that needs to change.
	PropertyPath string `json:"property_path"`

	// CurrentValue is the observed value from the snapshot.
	CurrentValue string `json:"current_value"`

	// RequiredValue is the value needed to satisfy the control.
	// Empty when HasSafeDefault is false (context-dependent).
	RequiredValue string `json:"required_value"`

	// RequiredValuePrompt is a natural-language question a downstream
	// consumer can use to elicit the correct value when
	// HasSafeDefault is false. Populated by propagation from the
	// control's RemediationSpec.RequiredValuePrompt when available.
	RequiredValuePrompt string `json:"required_value_prompt,omitempty"`

	// ResourceType is the AWS resource type this property belongs to.
	ResourceType string `json:"resource_type,omitempty"`

	// Description explains what this specific change does.
	Description string `json:"description"`

	// HasSafeDefault indicates whether Stave knows the required value
	// with high certainty (true) or it depends on context (false).
	HasSafeDefault bool `json:"has_safe_default"`
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

// HasAction reports whether the specification contains a concrete
// remediation instruction (the Action string is non-empty). Safe
// to call on a nil receiver. Replaces external probes of the form
// `spec.Action != ""` so the field check stays on the type that
// owns it.
func (s *RemediationSpec) HasAction() bool {
	return s != nil && s.Action != ""
}

// IsEmpty reports whether the spec carries neither a Description nor
// an Action — i.e. the catalog author left both prose fields blank,
// so a renderer has nothing to print. Distinct from Actionable, which
// asks specifically about Action; IsEmpty is the "should we render
// this block at all?" question. Safe on nil receivers.
func (s *RemediationSpec) IsEmpty() bool {
	return s == nil || (s.Description == "" && s.Action == "")
}
