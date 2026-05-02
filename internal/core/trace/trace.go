// Package trace defines the Logic Trace model — a structured audit trail
// that records how the safety engine arrived at every compliance verdict.
//
// A LogicTrace contains one Assessment per control×asset pairing. Each
// Assessment records the ordered steps the engine took (predicate evaluation,
// threshold check, coverage analysis) with inputs and results at each stage.
// This gives security researchers a "Proof of Pass" — not just why something
// failed, but why it was considered compliant.
package trace

import "time"

// SchemaVersion is the current version of the trace output format.
const SchemaVersion = "trace.v0.1"

// LogicTrace is the top-level audit trail for an evaluation run.
type LogicTrace struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	GeneratedAt   time.Time         `json:"generated_at"`
	StaveVersion  string            `json:"stave_version"`
	InputHashes   map[string]string `json:"input_hashes,omitempty"`
	Assessments   []Assessment      `json:"assessments"`
	Summary       Summary           `json:"summary"`
}

// Verdict is the typed outcome string an Assessment carries.
// Closed at the type level so callers stop comparing raw strings.
type Verdict string

// Recognised assessment verdicts.
const (
	VerdictViolation     Verdict = "VIOLATION"
	VerdictPass          Verdict = "PASS"
	VerdictSkipped       Verdict = "SKIPPED"
	VerdictInconclusive  Verdict = "INCONCLUSIVE"
	VerdictNotApplicable Verdict = "NOT_APPLICABLE"
)

// Assessment records the reasoning chain for a single control×asset evaluation.
type Assessment struct {
	ResourceID string  `json:"resource_id"`
	PolicyID   string  `json:"policy_id"`
	Verdict    Verdict `json:"verdict"`
	Confidence string  `json:"confidence"`
	Steps      []Step  `json:"steps"`
	FindingID  string  `json:"finding_id,omitempty"`
}

// IsViolation reports whether the assessment verdict is a violation.
func (a *Assessment) IsViolation() bool { return a != nil && a.Verdict == VerdictViolation }

// IsPass reports whether the assessment verdict is a pass.
func (a *Assessment) IsPass() bool { return a != nil && a.Verdict == VerdictPass }

// IsSkipped reports whether the assessment was skipped (not run).
func (a *Assessment) IsSkipped() bool { return a != nil && a.Verdict == VerdictSkipped }

// IsInconclusive reports whether the assessment is inconclusive,
// covering both the explicit INCONCLUSIVE verdict and the
// NOT_APPLICABLE verdict that ComputeSummary treats as the same
// inconclusive bucket.
func (a *Assessment) IsInconclusive() bool {
	if a == nil {
		return false
	}
	return a.Verdict == VerdictInconclusive || a.Verdict == VerdictNotApplicable
}

// Step records a single decision point in the evaluation reasoning chain.
// Input captures what the engine examined; Result captures what it concluded.
type Step struct {
	Name       string `json:"name"`
	Input      any    `json:"input,omitempty"`
	Result     any    `json:"result,omitempty"`
	DurationUS int64  `json:"duration_us,omitempty"`
}

// Summary provides aggregate counts for the trace output.
type Summary struct {
	TotalAssessments int `json:"total_assessments"`
	Violations       int `json:"violations"`
	Passes           int `json:"passes"`
	Skipped          int `json:"skipped"`
	Inconclusive     int `json:"inconclusive"`
}

// ComputeSummary derives summary counts from the assessment list.
// Uses the typed-verdict predicates on each Assessment so a future
// verdict-vocabulary change is one edit on the type, not a sweep
// through every counter.
func ComputeSummary(assessments []Assessment) Summary {
	var s Summary
	s.TotalAssessments = len(assessments)
	for i := range assessments {
		a := &assessments[i]
		switch {
		case a.IsViolation():
			s.Violations++
		case a.IsPass():
			s.Passes++
		case a.IsSkipped():
			s.Skipped++
		case a.IsInconclusive():
			s.Inconclusive++
		}
	}
	return s
}
