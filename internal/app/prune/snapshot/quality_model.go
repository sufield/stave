package snapshot

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// qualitySeverity classifies the severity of a snapshot quality issue.
type qualitySeverity string

const (
	severityError   qualitySeverity = "error"
	severityWarning qualitySeverity = "warning"
)

type qualityIssue struct {
	Code     string          `json:"code"`
	Severity qualitySeverity `json:"severity"`
	Message  string          `json:"message"`
	Evidence *issueEvidence  `json:"evidence,omitempty"`
}

// IsError reports whether this issue is recorded at the error
// severity. Replaces direct (Severity == severityError) probes in
// HasErrors so the constant comparison stays on the type that
// owns the field.
func (q *qualityIssue) IsError() bool {
	return q != nil && q.Severity == severityError
}

// IsWarning reports whether this issue is recorded at the warning
// severity. Sibling of IsError.
func (q *qualityIssue) IsWarning() bool {
	return q != nil && q.Severity == severityWarning
}

// issueEvidence holds typed evidence fields for quality issues.
// Each issue type populates only its relevant fields; the rest
// serialize as absent via omitempty.
type issueEvidence struct {
	// TOO_FEW_SNAPSHOTS
	MinSnapshots *int `json:"min_snapshots,omitempty"`
	Actual       *int `json:"actual,omitempty"`

	// LATEST_SNAPSHOT_STALE
	LatestCapturedAt string `json:"latest_captured_at,omitempty"`
	Age              string `json:"age,omitempty"`
	MaxStaleness     string `json:"max_staleness,omitempty"`

	// SNAPSHOT_GAP_TOO_LARGE
	MaxGapObserved string `json:"max_gap_observed,omitempty"`
	MaxGapAllowed  string `json:"max_gap_allowed,omitempty"`

	// MISSING_REQUIRED_RESOURCES
	MissingResources []string `json:"missing_resources,omitempty"`
}

type qualitySummary struct {
	Snapshots        int       `json:"snapshots"`
	OldestCapturedAt time.Time `json:"oldest_captured_at"`
	LatestCapturedAt time.Time `json:"latest_captured_at"`
	MaxGap           string    `json:"max_gap,omitempty"`
}

type qualityReport struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Kind          kernel.OutputKind `json:"kind"`
	CheckedAt     time.Time         `json:"checked_at"`
	Passed        bool              `json:"pass"`
	Strict        bool              `json:"strict"`
	Summary       qualitySummary    `json:"summary"`
	Issues        []qualityIssue    `json:"issues"`
}

// HasErrors reports whether at least one issue is recorded at the
// "error" severity. Replaces the open-coded scan in finalize() so
// the pass/fail computation can ask the report directly.
func (r qualityReport) HasErrors() bool {
	for i := range r.Issues {
		if r.Issues[i].IsError() {
			return true
		}
	}
	return false
}

// HasWarnings reports whether at least one issue is recorded at the
// "warning" severity. Sibling of HasErrors; together they let
// finalize collapse to one boolean expression instead of a
// per-issue switch.
func (r qualityReport) HasWarnings() bool {
	for i := range r.Issues {
		if r.Issues[i].IsWarning() {
			return true
		}
	}
	return false
}

// qualityParams defines inputs for snapshot quality assessment.
type qualityParams struct {
	Snapshots         []asset.Snapshot
	Now               time.Time
	MinSnapshots      int
	MaxStaleness      time.Duration
	MaxGap            time.Duration
	RequiredResources []string
	Strict            bool
}

type qualityAssessor struct {
	params qualityParams
	report qualityReport
	sorted []asset.Snapshot
}
