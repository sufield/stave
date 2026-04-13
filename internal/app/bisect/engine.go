package bisect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Evaluator assesses a single snapshot against a control and reports
// whether the control is violated for any (or a specific) resource.
type Evaluator func(ctx context.Context, snap asset.Snapshot) (bool, error)

// Engine orchestrates the bisect or scan search.
type Engine struct {
	Evaluate Evaluator
}

// Run executes the search over the given snapshots.
func (e *Engine) Run(ctx context.Context, snapshots []asset.Snapshot, mode Mode, controlID string, resourceARN string) (Result, error) {
	if len(snapshots) == 0 {
		return Result{}, errors.New("no snapshots to search")
	}

	result := Result{
		Mode:           mode,
		ControlID:      controlID,
		ResourceARN:    resourceARN,
		SnapshotsTotal: len(snapshots),
	}

	switch mode {
	case ModeBisect:
		return e.runBisect(ctx, snapshots, result)
	case ModeScan:
		return e.runScan(ctx, snapshots, result)
	default:
		return Result{}, fmt.Errorf("unknown bisect mode: %d", mode)
	}
}

func (e *Engine) runBisect(ctx context.Context, snapshots []asset.Snapshot, result Result) (Result, error) {
	n := len(snapshots)

	// Pre-check: does the latest snapshot even have a violation?
	latestViolated, err := e.eval(ctx, snapshots[n-1], &result)
	if err != nil {
		return result, err
	}
	if !latestViolated {
		result.IsMonotonic = true
		return result, nil // no current violation
	}

	// Pre-check: does the earliest snapshot already have a violation?
	earliestViolated, err := e.eval(ctx, snapshots[0], &result)
	if err != nil {
		return result, err
	}
	if earliestViolated {
		// Violation predates the archive.
		result.Windows = []ViolationWindow{{
			EntryAfter: snapshots[0].CapturedAt,
			IsOngoing:  true,
		}}
		result.IsMonotonic = true
		result.Delta = computeDelta(snapshots[0], snapshots[0])
		return result, nil
	}

	// Binary search: snapshots[low] is PASS, snapshots[high] is FAIL.
	low, high := 0, n-1
	for high-low > 1 {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		mid := (low + high) / 2
		violated, evalErr := e.eval(ctx, snapshots[mid], &result)
		if evalErr != nil {
			return result, evalErr
		}
		if violated {
			high = mid
		} else {
			low = mid
		}
	}

	result.Windows = []ViolationWindow{{
		EntryBefore: snapshots[low].CapturedAt,
		EntryAfter:  snapshots[high].CapturedAt,
		IsOngoing:   true,
	}}
	result.Delta = computeDelta(snapshots[low], snapshots[high])

	// Post-check for non-monotonicity: sample a few points before low
	// to detect if earlier violations existed (fix → re-break pattern).
	result.IsMonotonic = true
	for i := 0; i < low; i += max(1, low/4) {
		v, sErr := e.eval(ctx, snapshots[i], &result)
		if sErr != nil {
			break
		}
		if v {
			result.IsMonotonic = false
			break
		}
	}

	return result, nil //nolint:nilerr // monotonicity check is best-effort; main bisect result is already valid
}

func (e *Engine) runScan(ctx context.Context, snapshots []asset.Snapshot, result Result) (Result, error) {
	inViolation := false
	var currentWindow *ViolationWindow

	for i, snap := range snapshots {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		violated, evalErr := e.eval(ctx, snap, &result)
		if evalErr != nil {
			return result, evalErr
		}

		if violated && !inViolation {
			// Transition: PASS → VIOLATION (new window opens).
			w := ViolationWindow{
				EntryAfter: snap.CapturedAt,
				IsOngoing:  true,
			}
			if i > 0 {
				w.EntryBefore = snapshots[i-1].CapturedAt
			}
			result.Windows = append(result.Windows, w)
			currentWindow = &result.Windows[len(result.Windows)-1]
			inViolation = true
		} else if !violated && inViolation {
			// Transition: VIOLATION → PASS (window closes).
			if currentWindow != nil {
				currentWindow.ExitBefore = snapshots[i-1].CapturedAt
				currentWindow.ExitAfter = snap.CapturedAt
				currentWindow.IsOngoing = false
				// Update the slice element (pointer was to local copy).
				result.Windows[len(result.Windows)-1] = *currentWindow
			}
			currentWindow = nil
			inViolation = false
		}
	}

	// Compute delta for the first window if any exist.
	if len(result.Windows) > 0 {
		w := result.Windows[0]
		if !w.EntryBefore.IsZero() {
			before := findSnapshotAt(snapshots, w.EntryBefore)
			after := findSnapshotAt(snapshots, w.EntryAfter)
			if before != nil && after != nil {
				result.Delta = computeDelta(*before, *after)
			}
		}
	}

	result.IsMonotonic = len(result.Windows) <= 1
	return result, nil
}

func (e *Engine) eval(ctx context.Context, snap asset.Snapshot, result *Result) (bool, error) {
	result.AssessmentsRun++
	return e.Evaluate(ctx, snap)
}

func computeDelta(before, after asset.Snapshot) *asset.InfrastructureDrift {
	drift := asset.ComputeDrift(before, after)
	return &drift
}

func findSnapshotAt(snapshots []asset.Snapshot, t time.Time) *asset.Snapshot {
	for i := range snapshots {
		if snapshots[i].CapturedAt.Equal(t) {
			return &snapshots[i]
		}
	}
	return nil
}

// MakeEvaluator creates an Evaluator that assesses a single control against
// a snapshot. It checks whether any finding exists for the given control ID
// (and optionally scoped to a specific resource ARN).
func MakeEvaluator(
	assess func(snapshots []asset.Snapshot) (evaluation.ComplianceReport, error),
	controlID kernel.ControlID,
	resourceARN string,
) Evaluator {
	return func(ctx context.Context, snap asset.Snapshot) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		report, err := assess([]asset.Snapshot{snap, snap}) // two identical snapshots for lifecycle
		if err != nil {
			return false, fmt.Errorf("assess snapshot at %s: %w", snap.CapturedAt, err)
		}
		return hasViolation(&report, controlID, resourceARN), nil
	}
}

func hasViolation(report *evaluation.ComplianceReport, controlID kernel.ControlID, resourceARN string) bool {
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.ControlID != controlID {
			continue
		}
		if resourceARN != "" && f.AssetID.String() != resourceARN {
			continue
		}
		return true
	}
	return false
}

// FindControl looks up a control by ID in a slice.
func FindControl(controls []policy.ControlDefinition, id kernel.ControlID) (policy.ControlDefinition, bool) {
	for i := range controls {
		if controls[i].ID == id {
			return controls[i], true
		}
	}
	return policy.ControlDefinition{}, false
}
