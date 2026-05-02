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

// IsPass reports whether the record's verdict is a pass.
// Centralised so callers stop comparing e.Verdict against the
// constant directly. Mirrors evaluation.ResourceCheck.IsPass.
func (e *EvidenceRecord) IsPass() bool {
	return e != nil && e.Verdict == VerdictPass
}

// IsFail reports whether the record's verdict is a fail.
func (e *EvidenceRecord) IsFail() bool {
	return e != nil && e.Verdict == VerdictFail
}

// IsIncomplete reports whether the record's verdict is incomplete —
// usually missing data or a degraded predicate evaluation rather
// than a definite pass/fail.
func (e *EvidenceRecord) IsIncomplete() bool {
	return e != nil && e.Verdict == VerdictIncomplete
}

// IsGap reports whether this record represents a coverage gap —
// either a failing control or an incomplete evaluation. Used by
// the compliance exporter to drive the gap-collection pass; the
// (Fail || Incomplete) disjunction lives on the record so callers
// stop joining the two predicates at every site.
func (e *EvidenceRecord) IsGap() bool {
	return e.IsFail() || e.IsIncomplete()
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
