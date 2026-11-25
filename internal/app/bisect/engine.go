package bisect

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
func (e *Engine) Run(ctx context.Context, snapshots []asset.Snapshot, mode Mode, controlID kernel.ControlID, resourceARN asset.ID) (Result, error) {
	if e == nil || e.Evaluate == nil {
		return Result{}, errors.New("bisect: evaluator function is required")
	}
	if len(snapshots) == 0 {
		return Result{}, errors.New("no snapshots to search")
	}

	sorted := make([]asset.Snapshot, len(snapshots))
	copy(sorted, snapshots)
	slices.SortFunc(sorted, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})

	result := Result{
		Mode:           mode,
		ControlID:      controlID,
		ResourceARN:    resourceARN,
		SnapshotsTotal: SnapshotCount(len(sorted)),
	}

	switch mode {
	case ModeBisect:
		return e.runBisect(ctx, sorted, result)
	case ModeScan:
		return e.runScan(ctx, sorted, result)
	default:
		return Result{}, fmt.Errorf("unknown bisect mode: %s", mode)
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
		// Delta compares oldest vs newest so the operator sees what
		// changed across the archive's lifetime — comparing
		// snapshots[0] to itself produced an empty delta and made
		// the report look as if nothing had changed despite an
		// ongoing violation.
		delta, dErr := computeDelta(snapshots[0], snapshots[len(snapshots)-1])
		if dErr != nil {
			return result, fmt.Errorf("compute delta (earliest violation): %w", dErr)
		}
		result.Delta = delta
		return result, nil
	}

	// Binary search: snapshots[low] is PASS, snapshots[high] is FAIL.
	low, high := 0, n-1
	for high-low > 1 {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("err: %w", err)
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
	delta, dErr := computeDelta(snapshots[low], snapshots[high])
	if dErr != nil {
		return result, fmt.Errorf("compute delta (bisect window): %w", dErr)
	}
	result.Delta = delta

	result.IsMonotonic = e.checkMonotonicity(ctx, snapshots[:low], &result)

	return result, nil //nolint:nilerr // monotonicity check is best-effort; main bisect result is already valid
}

func (e *Engine) checkMonotonicity(ctx context.Context, before []asset.Snapshot, result *Result) bool {
	low := len(before)
	if low == 0 {
		return true
	}
	visitedBoundary := false
	for i := 0; i < low; i += max(1, low/4) {
		if i == low-1 {
			visitedBoundary = true
		}
		v, sErr := e.eval(ctx, before[i], result)
		if sErr != nil {
			break
		}
		if v {
			return false
		}
	}
	if !visitedBoundary {
		v, sErr := e.eval(ctx, before[low-1], result)
		if sErr == nil && v {
			return false
		}
	}
	return true
}

func (e *Engine) runScan(ctx context.Context, snapshots []asset.Snapshot, result Result) (Result, error) {
	inViolation := false
	currentWindowIdx := -1

	for i, snap := range snapshots {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("err: %w", err)
		}
		violated, evalErr := e.eval(ctx, snap, &result)
		if evalErr != nil {
			return result, evalErr
		}

		if violated && !inViolation {
			currentWindowIdx = openWindow(&result, snapshots, i)
			inViolation = true
		} else if !violated && inViolation {
			closeWindow(&result, snapshots, i, currentWindowIdx)
			currentWindowIdx = -1
			inViolation = false
		}
	}

	if err := computeFirstWindowDelta(snapshots, &result); err != nil {
		return result, err
	}
	result.IsMonotonic = len(result.Windows) <= 1
	return result, nil
}

// openWindow appends a new violation window and returns its index.
func openWindow(result *Result, snapshots []asset.Snapshot, i int) int {
	w := ViolationWindow{
		EntryAfter: snapshots[i].CapturedAt,
		IsOngoing:  true,
	}
	if i > 0 {
		w.EntryBefore = snapshots[i-1].CapturedAt
	}
	result.Windows = append(result.Windows, w)
	return len(result.Windows) - 1
}

// closeWindow marks the window at idx as closed.
func closeWindow(result *Result, snapshots []asset.Snapshot, i, idx int) {
	if idx < 0 {
		return
	}
	result.Windows[idx].ExitBefore = snapshots[i-1].CapturedAt
	result.Windows[idx].ExitAfter = snapshots[i].CapturedAt
	result.Windows[idx].IsOngoing = false
}

func computeFirstWindowDelta(snapshots []asset.Snapshot, result *Result) error {
	if len(result.Windows) == 0 {
		return nil
	}
	w := result.Windows[0]
	if w.EntryBefore.IsZero() {
		return nil
	}
	before := findSnapshotAt(snapshots, w.EntryBefore)
	after := findSnapshotAt(snapshots, w.EntryAfter)
	if before == nil || after == nil {
		return nil
	}
	delta, err := computeDelta(*before, *after)
	if err != nil {
		return fmt.Errorf("compute delta (scan window): %w", err)
	}
	result.Delta = delta
	return nil
}

func (e *Engine) eval(ctx context.Context, snap asset.Snapshot, result *Result) (bool, error) {
	result.AssessmentsRun++
	return e.Evaluate(ctx, snap)
}

func computeDelta(before, after asset.Snapshot) (*asset.InfrastructureDrift, error) {
	drift, err := asset.ComputeDrift(before, after)
	if err != nil {
		return nil, fmt.Errorf("compute drift: %w", err)
	}
	return &drift, nil
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
	resourceARN asset.ID,
) Evaluator {
	return func(ctx context.Context, snap asset.Snapshot) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("err: %w", err)
		}
		report, err := assess([]asset.Snapshot{snap, snap}) // two identical snapshots for lifecycle
		if err != nil {
			return false, fmt.Errorf("assess snapshot at %s: %w", snap.CapturedAt, err)
		}
		return hasViolation(&report, controlID, resourceARN), nil
	}
}

func hasViolation(report *evaluation.ComplianceReport, controlID kernel.ControlID, resourceARN asset.ID) bool {
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.ControlID != controlID {
			continue
		}
		if resourceARN != "" && f.AssetID != resourceARN {
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
