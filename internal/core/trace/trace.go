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

// Assessment records the reasoning chain for a single control×asset evaluation.
type Assessment struct {
	ResourceID string `json:"resource_id"`
	PolicyID   string `json:"policy_id"`
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence"`
	Steps      []Step `json:"steps"`
	FindingID  string `json:"finding_id,omitempty"`
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
func ComputeSummary(assessments []Assessment) Summary {
	var s Summary
	s.TotalAssessments = len(assessments)
	for i := range assessments {
		switch assessments[i].Verdict {
		case "VIOLATION":
			s.Violations++
		case "PASS":
			s.Passes++
		case "SKIPPED":
			s.Skipped++
		case "INCONCLUSIVE", "NOT_APPLICABLE":
			s.Inconclusive++
		}
	}
	return s
}
