package engine

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/internal/adapters/telemetry"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/testutil"
)

// These tests demonstrate the builder pattern — compare the setup verbosity
// with the 15-line literal construction in engine_extra2_test.go.

func TestBuilder_BasicViolation(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.A.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withSLA(1 * time.Hour).
		withControls(ctl).
		alwaysUnsafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps)
	testutil.AssertNoError(t, err)
	testutil.AssertViolationCount(t, &result, 1)
	testutil.AssertSecurityState(t, &result, evaluation.StateNonCompliant)
}

func TestBuilder_CompliantResult(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.A.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps)
	testutil.AssertNoError(t, err)
	testutil.AssertSecurityState(t, &result, evaluation.StateCompliant)
	testutil.AssertViolationCount(t, &result, 0)
}

func TestBuilder_WithTracer(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.A.001").typed(policy.TypeUnsafeState).build()
	tracer := telemetry.NewLocalFileTracer()

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withSLA(1 * time.Hour).
		withControls(ctl).
		alwaysUnsafe().
		withTracer(tracer).
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps)
	testutil.AssertNoError(t, err)
	testutil.AssertViolationCount(t, &result, 1)

	// Verify the tracer captured the assessment trace with reasoning steps.
	lt := tracer.Finalize(ports.FinalizeArgs{RunID: "test-run", StaveVersion: "test"})
	testutil.AssertTraceHasAssessment(t, lt, "bucket-1", "CTL.A.001", "VIOLATION")

	assessment := lt.Assessments[0]
	testutil.AssertTraceStep(t, assessment, "exemption_check")
	testutil.AssertTraceStep(t, assessment, "predicate_evaluation")
}
