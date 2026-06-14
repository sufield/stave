package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sufield/stave/internal/adapters/telemetry"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/ports"
)

// TestConcurrency_AssessHighContention stresses the parallel assessor's shared
// write paths under the race detector. Run with: go test -race -count=N.
//
// It saturates the per-control goroutine pool (controls far exceeding NumCPU)
// against an asset set SHARED by every control, so many goroutines hit the same
// collector stripes (RecordSeenAsset / RecordCheck / RecordFindings), the same
// finding pool (borrow/return), and a single LocalFileTracer concurrently
// (BeginAssessment on every control×asset, End → append under the tracer mutex).
// The existing WithTracer test uses one control × one asset, so this is the
// first coverage of the concurrent tracer-append and high-contention stripe
// paths.
//
// Two invariants are asserted across repeated runs:
//   - race freedom (the -race build is the real check), and
//   - determinism: identical inputs yield an identical violation count and an
//     identical (sorted) finding ordering, regardless of goroutine scheduling.
func TestConcurrency_AssessHighContention(t *testing.T) {
	t.Parallel()

	const (
		numControls = 64 // >> NumCPU so the errgroup pool stays saturated
		numAssets   = 32 // shared across every control -> same-stripe contention
	)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	controls := make([]policy.ControlDefinition, numControls)
	for i := range controls {
		controls[i] = newTestControl(fmt.Sprintf("CTL.STRESS.%03d", i)).
			typed(policy.TypeUnsafeState).
			build()
	}

	assetIDs := make([]string, numAssets)
	for i := range assetIDs {
		assetIDs[i] = fmt.Sprintf("bucket-%02d", i)
	}
	snaps := newLifecycleBuilder(base).
		at(0, assetIDs...).
		at(48*time.Hour, assetIDs...).
		build()

	run := func() (violations int, order []string) {
		tracer := telemetry.NewLocalFileTracer()
		a := newTestAssessor().
			withClock(base.Add(72 * time.Hour)).
			withSLA(1 * time.Hour).
			withControls(controls...).
			alwaysUnsafe().
			withTracer(tracer).
			build()

		result, err := a.Assess(context.Background(), snaps)
		if err != nil {
			t.Fatalf("Assess: %v", err)
		}
		// Touch the tracer's accumulated state too, exercising the
		// locked Finalize read of everything the concurrent spans appended.
		lt := tracer.Finalize(ports.FinalizeArgs{RunID: "stress", StaveVersion: "test"})
		if len(lt.Assessments) == 0 {
			t.Fatalf("tracer captured no assessments")
		}
		findings := result.Findings
		ids := make([]string, len(findings))
		for i := range findings {
			ids[i] = string(findings[i].FindingID)
		}
		return len(findings), ids
	}

	wantViolations, wantOrder := run()
	// Every control violates every shared asset exactly once.
	if wantViolations != numControls*numAssets {
		t.Fatalf("violations = %d, want %d (numControls*numAssets)", wantViolations, numControls*numAssets)
	}

	// Determinism: repeat and require byte-identical finding ordering. A
	// concurrency bug (lost/duplicated finding, scheduling-dependent order
	// escaping the sort) shows up as a mismatch here even when -race is quiet.
	for iter := range 5 {
		gotViolations, gotOrder := run()
		if gotViolations != wantViolations {
			t.Fatalf("iter %d: violations = %d, want %d (nondeterministic count)", iter, gotViolations, wantViolations)
		}
		if len(gotOrder) != len(wantOrder) {
			t.Fatalf("iter %d: finding count drift %d vs %d", iter, len(gotOrder), len(wantOrder))
		}
		for j := range gotOrder {
			if gotOrder[j] != wantOrder[j] {
				t.Fatalf("iter %d: finding order diverged at %d: %q vs %q (nondeterministic output)",
					iter, j, gotOrder[j], wantOrder[j])
			}
		}
	}
}
