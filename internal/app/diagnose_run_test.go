package app

import (
	"context"
	"testing"
	"time"

	s3 "github.com/sufield/stave/internal/adapters/aws/s3"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"

	"github.com/sufield/stave/internal/core/asset"

	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	clockadp "github.com/sufield/stave/internal/core/ports"
)

func TestDiagnoseExecuteAndLoaders(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	ctl := policy.ControlDefinition{
		ID:          "CTL.TEST.PUBLIC.001",
		Name:        "Public resource",
		Description: "Detect public resources",
		Type:        policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
	}
	resource := asset.Asset{
		ID:         "res-1",
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     kernel.Vendor("aws"),
		Properties: map[string]any{"public": true},
	}
	snapshots := []asset.Snapshot{
		{
			GeneratedBy: &asset.GeneratedBy{SourceType: s3.SourceTypeAWSS3Snapshot},
			CapturedAt:  now.Add(-2 * time.Hour),
			Assets:      []asset.Asset{resource},
		},
		{
			GeneratedBy: &asset.GeneratedBy{SourceType: s3.SourceTypeAWSS3Snapshot},
			CapturedAt:  now.Add(-1 * time.Hour),
			Assets:      []asset.Asset{resource},
		},
	}

	run, newErr := appdiagnose.NewRun(
		evalObservationRepoStub{snapshots: snapshots},
		evalControlRepoStub{controls: []policy.ControlDefinition{ctl}},
	)
	if newErr != nil {
		t.Fatal(newErr)
	}

	t.Run("uses previous result when provided", func(t *testing.T) {
		previousResult := &evaluation.Audit{Findings: []evaluation.Finding{}}
		report, err := run.Execute(context.Background(), appdiagnose.Config{
			ControlsDir:       "ctl",
			ObservationsDir:   "obs",
			PreviousResult:    previousResult,
			MaxUnsafeDuration: 30 * time.Minute,
			Clock:             clockadp.FixedClock(now),
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if report == nil {
			t.Fatal("expected report")
		}
		if report.Summary.TotalControls != 1 {
			t.Fatalf("total controls=%d, want 1", report.Summary.TotalControls)
		}
	})

	t.Run("evaluates fresh when no previous result", func(t *testing.T) {
		// Fresh evaluation with a properly prepared control.
		preparedCtl := ctl
		preparedCtl.Prepare()
		preparedRun, newErr := appdiagnose.NewRun(
			evalObservationRepoStub{snapshots: snapshots},
			evalControlRepoStub{controls: []policy.ControlDefinition{preparedCtl}},
		)
		if newErr != nil {
			t.Fatal(newErr)
		}
		report, err := preparedRun.Execute(context.Background(), appdiagnose.Config{
			ControlsDir:       "ctl",
			ObservationsDir:   "obs",
			MaxUnsafeDuration: 30 * time.Minute,
			Clock:             clockadp.FixedClock(now),
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if report == nil {
			t.Fatal("expected report")
		}
	})
}

func TestDiagnoseExecute_NilPreviousResultRunsFreshEvaluation(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	ctl := policy.ControlDefinition{
		ID:   "CTL.TEST.001",
		Name: "test",
		Type: policy.TypeUnsafeDuration,
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatal(err)
	}

	run, newErr := appdiagnose.NewRun(
		evalObservationRepoStub{snapshots: []asset.Snapshot{{CapturedAt: now}}},
		evalControlRepoStub{controls: []policy.ControlDefinition{ctl}},
	)
	if newErr != nil {
		t.Fatal(newErr)
	}

	report, err := run.Execute(context.Background(), appdiagnose.Config{
		ControlsDir:       "ctl",
		ObservationsDir:   "obs",
		MaxUnsafeDuration: time.Hour,
		Clock:             clockadp.FixedClock(now),
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
}
