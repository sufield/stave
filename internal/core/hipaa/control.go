package hipaa

import "github.com/sufield/stave/internal/core/asset"

// Control is a programmatic safety check evaluated against an observation
// snapshot. Each control has a unique ID, severity, and produces a Result
// describing whether the check passed or failed with actionable remediation.
type Control interface {
	// ID returns the unique control identifier (e.g. "ACCESS.001").
	ID() string

	// Description returns a human-readable summary of what this control checks.
	Description() string

	// Severity returns the impact level of a violation.
	Severity() Severity

	// ComplianceProfiles returns the compliance frameworks this control
	// is relevant to (e.g. "hipaa", "pci-dss", "cis-s3").
	ComplianceProfiles() []string

	// ComplianceRefs returns the compliance citation map.
	ComplianceRefs() map[string]string

	// ProfileRationale returns the rationale for inclusion in the named profile.
	ProfileRationale(profile string) string

	// ProfileSeverityOverride returns the severity override for the named profile, if any.
	ProfileSeverityOverride(profile string) (Severity, bool)

	// Evaluate runs the control against a snapshot and returns a Result.
	Evaluate(snap asset.Snapshot) Result
}

// Result captures the outcome of evaluating a single control against a snapshot.
type Result struct {
	// Pass is true when the control holds (no violation detected).
	Pass bool `json:"pass"`

	// ControlID identifies which control produced this result.
	ControlID string `json:"control_id"`

	// Severity is the impact level of the control.
	Severity Severity `json:"severity"`

	// Finding describes what failed in practitioner language.
	// Empty when Pass is true.
	Finding string `json:"finding,omitempty"`

	// Remediation provides concrete steps to fix the violation.
	// Empty when Pass is true.
	Remediation string `json:"remediation,omitempty"`

	// ComplianceRefs maps compliance profile names to specific citations
	// (e.g. "hipaa" → "§164.312(b)").
	ComplianceRefs map[string]string `json:"compliance_refs,omitempty"`
}

// --- Functional options for control construction ---

// Definition holds the configurable fields for building an control.
// Use With* options to populate fields, then pass to a constructor.
type Definition struct {
	id                 string
	description        string
	severity           Severity
	complianceProfiles []string
	complianceRefs     map[string]string
	profileRationales  map[string]string
	profileSeverities  map[string]Severity
}

// Option configures a Definition.
type Option func(*Definition)

// WithID sets the control identifier.
func WithID(id string) Option {
	return func(d *Definition) { d.id = id }
}

// WithDescription sets the human-readable description.
func WithDescription(desc string) Option {
	return func(d *Definition) { d.description = desc }
}

// WithSeverity sets the impact level.
func WithSeverity(s Severity) Option {
	return func(d *Definition) { d.severity = s }
}

// WithComplianceProfiles sets the applicable compliance frameworks.
func WithComplianceProfiles(profiles ...string) Option {
	return func(d *Definition) { d.complianceProfiles = profiles }
}

// WithComplianceRef adds a compliance citation for a specific profile.
func WithComplianceRef(profile, citation string) Option {
	return func(d *Definition) {
		if d.complianceRefs == nil {
			d.complianceRefs = make(map[string]string)
		}
		d.complianceRefs[profile] = citation
	}
}

// WithProfileSeverityOverride sets a severity override for a specific profile.
func WithProfileSeverityOverride(profile string, sev Severity) Option {
	return func(d *Definition) {
		if d.profileSeverities == nil {
			d.profileSeverities = make(map[string]Severity)
		}
		d.profileSeverities[profile] = sev
	}
}

// WithProfileRationale sets the rationale for inclusion in a specific profile.
func WithProfileRationale(profile, rationale string) Option {
	return func(d *Definition) {
		if d.profileRationales == nil {
			d.profileRationales = make(map[string]string)
		}
		d.profileRationales[profile] = rationale
	}
}

// NewDefinition applies all options and returns the populated Definition.
func NewDefinition(opts ...Option) Definition {
	var d Definition
	for _, opt := range opts {
		opt(&d)
	}
	return d
}

// Getters for Definition fields (used by control implementations).

// ID returns the control identifier.
func (d Definition) ID() string { return d.id }

// Description returns the human-readable description.
func (d Definition) Description() string { return d.description }

// Severity returns the impact level.
func (d Definition) Severity() Severity { return d.severity }

// ComplianceProfiles returns the applicable compliance frameworks.
func (d Definition) ComplianceProfiles() []string { return d.complianceProfiles }

// ComplianceRefs returns the compliance citation map.
func (d Definition) ComplianceRefs() map[string]string { return d.complianceRefs }

// ProfileRationale returns the rationale for inclusion in the named profile.
func (d Definition) ProfileRationale(profile string) string {
	return d.profileRationales[profile]
}

// ProfileSeverityOverride returns the severity override for the named profile, if any.
func (d Definition) ProfileSeverityOverride(profile string) (Severity, bool) {
	s, ok := d.profileSeverities[profile]
	return s, ok
}

// PassResult returns a passing Result for this definition.
func (d Definition) PassResult() Result {
	return Result{
		Pass:      true,
		ControlID: d.id,
		Severity:  d.severity,
	}
}

// FailResult returns a failing Result for this definition with the given
// finding description and remediation steps.
func (d Definition) FailResult(finding, remediation string) Result {
	return Result{
		Pass:           false,
		ControlID:      d.id,
		Severity:       d.severity,
		Finding:        finding,
		Remediation:    remediation,
		ComplianceRefs: d.complianceRefs,
	}
}
