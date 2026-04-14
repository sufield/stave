// Package evidence defines the typed evidence model for compliance
// evidence packages. An EvidenceRecord binds a control evaluation
// verdict to specific regulatory citations with a complete reasoning
// trace.
package evidence

import "time"

// EvidenceVerdict is the outcome of a control evaluation for evidence purposes.
type EvidenceVerdict int

const (
	VerdictPass EvidenceVerdict = iota
	VerdictFail
	VerdictIncomplete
	VerdictNotApplicable
)

// String returns the wire-format name of the verdict.
func (v EvidenceVerdict) String() string {
	switch v {
	case VerdictPass:
		return "pass"
	case VerdictFail:
		return "fail"
	case VerdictIncomplete:
		return "incomplete"
	case VerdictNotApplicable:
		return "not_applicable"
	default:
		return "unknown"
	}
}

// EvidenceRecord is the typed evidence artifact for a single control
// evaluation against a specific compliance citation.
type EvidenceRecord struct {
	ControlID      string          `json:"control_id"`
	ControlName    string          `json:"control_name"`
	ResourceARN    string          `json:"resource_arn"`
	SnapshotID     string          `json:"snapshot_id"`
	Verdict        EvidenceVerdict `json:"verdict"`
	Severity       string          `json:"severity"`
	Citations      []Citation      `json:"citations"`
	ReasoningTrace ReasoningTrace  `json:"reasoning_trace"`
	EvaluatedAt    time.Time       `json:"evaluated_at"`
}

// Citation is a single regulatory reference with structured fields.
type Citation struct {
	Framework   string `json:"framework" yaml:"framework"`
	Requirement string `json:"requirement" yaml:"requirement"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// ReasoningTrace captures the observations and logic that produced the verdict.
type ReasoningTrace struct {
	ObservationProperties []ObservationProperty `json:"observation_properties,omitempty"`
	InvariantEvaluated    string                `json:"invariant_evaluated,omitempty"`
	FailCondition         string                `json:"fail_condition,omitempty"`
	FindingMessage        string                `json:"finding_message,omitempty"`
}

// ObservationProperty is a single observed property from the snapshot.
type ObservationProperty struct {
	Field string `json:"field"`
	Value string `json:"value"`
}
