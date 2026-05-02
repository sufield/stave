// Package bisect implements the security chronology engine — forensic
// search through snapshot history to find when an invariant was first violated.
package bisect

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// Mode selects the search strategy.
type Mode int

const (
	// ModeBisect uses binary search to find the transition into the current
	// violation window. O(log N) assessments. Correct only when the history
	// is monotonic (once violated, stays violated).
	ModeBisect Mode = iota
	// ModeScan uses linear scan to find ALL violation windows. O(N)
	// assessments. Correct for non-monotonic histories.
	ModeScan
)

// ViolationWindow represents a contiguous period where an invariant was violated.
type ViolationWindow struct {
	// EntryBefore is the timestamp of the last PASS before the violation.
	// Zero if the violation predates the archive.
	EntryBefore time.Time `json:"entry_before"`
	// EntryAfter is the timestamp of the first VIOLATION in this window.
	EntryAfter time.Time `json:"entry_after"`
	// ExitBefore is the timestamp of the last VIOLATION before remediation.
	// Zero if the window is ongoing.
	ExitBefore time.Time `json:"exit_before"`
	// ExitAfter is the timestamp of the first PASS after remediation.
	// Zero if the window is ongoing.
	ExitAfter time.Time `json:"exit_after"`
	// IsOngoing is true when the violation has not been remediated.
	IsOngoing bool `json:"is_ongoing"`
}

// Result holds the output of a bisect or scan operation.
type Result struct {
	Mode           Mode                       `json:"mode"`
	ControlID      string                     `json:"control_id"`
	ResourceARN    string                     `json:"resource_arn,omitempty"`
	SnapshotsTotal int                        `json:"snapshots_total"`
	AssessmentsRun int                        `json:"assessments_run"`
	Windows        []ViolationWindow          `json:"windows,omitempty"`
	IsMonotonic    bool                       `json:"is_monotonic"`
	Delta          *asset.InfrastructureDrift `json:"delta,omitempty"`
}

// HasViolation reports whether any violation window was found.
func (r Result) HasViolation() bool {
	return len(r.Windows) > 0
}

// IsScanMode reports whether the result was produced by ModeScan.
// Replaces (result.Mode == appbisect.ModeScan) probes in cmd/bisect
// so the renderer asks the result for its mode-shape rather than
// comparing the field to a constant.
func (r Result) IsScanMode() bool {
	return r.Mode == ModeScan
}

// IsBisectMode reports whether the result was produced by ModeBisect.
// Sibling of IsScanMode for the binary-search strategy.
func (r Result) IsBisectMode() bool {
	return r.Mode == ModeBisect
}
