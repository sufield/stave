// Package bisect implements the security chronology engine — forensic
// search through snapshot history to find when an invariant was first violated.
package bisect

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// Mode selects the search strategy.
type Mode string

const (
	// ModeBisect uses binary search to find the transition into the current
	// violation window. O(log N) assessments. Correct only when the history
	// is monotonic (once violated, stays violated).
	ModeBisect Mode = "BISECT"
	// ModeScan uses linear scan to find ALL violation windows. O(N)
	// assessments. Correct for non-monotonic histories.
	ModeScan Mode = "SCAN"
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
	ControlID      kernel.ControlID           `json:"control_id"`
	ResourceARN    asset.ID                   `json:"resource_arn,omitempty"`
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

// ShouldWarnMultipleWindows reports whether the cmd/bisect output
// renderer should print a warning that the bisect search may have
// missed earlier violation windows. Triggered when the history is
// non-monotonic AND the search ran in bisect mode (scan mode finds
// every window, so no warning needed). Replaces the
// (!IsMonotonic && IsBisectMode()) compound check at
// cmd/bisect/output.go.
func (r Result) ShouldWarnMultipleWindows() bool {
	return !r.IsMonotonic && r.IsBisectMode()
}

// ModeLabel returns the uppercase mode tag the cmd/bisect text
// renderer prints in the headline ("SCAN" or "BISECT"). Replaces
// the inline (IsScanMode ? "SCAN" : "BISECT") branch so the
// rendering choice stays on the type that owns Mode.
func (r Result) ModeLabel() string {
	if r.IsScanMode() {
		return "SCAN"
	}
	return "BISECT"
}

// HasPatientZero reports whether this result has a "patient zero"
// (earliest-ever) window worth surfacing in the output. True only
// in scan mode with multiple windows — bisect mode finds the
// current window but cannot name the historical first.
func (r Result) HasPatientZero() bool {
	return r.IsScanMode() && len(r.Windows) > 1
}
