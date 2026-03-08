package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/asset"

	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	clockadp "github.com/sufield/stave/internal/domain/ports"
)

type evalResultRepoStub struct {
	result *evaluation.Result
	err    error
}

func (s evalResultRepoStub) LoadFromFile(_ string) (*evaluation.Result, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	return &evaluation.Result{}, nil
}

func (s evalResultRepoStub) LoadFromReader(_ io.Reader, _ string) (*evaluation.Result, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	return &evaluation.Result{}, nil
}

func TestDiagnoseExecuteAndLoaders(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	ctl := policy.ControlDefinition{
		ID:          "CTL.TEST.PUBLIC.001",
		Name:        "Public resource",
		Description: "Detect public resources",
		Type:        policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: "properties.public", Op: "eq", Value: true},
			},
		},
	}
	resource := asset.Asset{
		ID:         "res-1",
		Type:       kernel.TypeS3Bucket,
		Vendor:     kernel.VendorAWS,
		Properties: map[string]any{"public": true},
	}
	snapshots := []asset.Snapshot{
		{
			GeneratedBy: &asset.GeneratedBy{SourceType: "terraform.plan_json"},
			CapturedAt:  now.Add(-2 * time.Hour),
			Assets:      []asset.Asset{resource},
		},
		{
			GeneratedBy: &asset.GeneratedBy{SourceType: "terraform.plan_json"},
			CapturedAt:  now.Add(-1 * time.Hour),
			Assets:      []asset.Asset{resource},
		},
	}

	evalStub := evalResultRepoStub{}
	run, newErr := appdiagnose.NewRun(
		evalObservationRepoStub{snapshots: snapshots},
		evalControlRepoStub{controls: []policy.ControlDefinition{ctl}},
		evalStub,
		evalStub,
	)
	if newErr != nil {
		t.Fatal(newErr)
	}

	t.Run("uses output reader when provided", func(t *testing.T) {
		reader := bytes.NewBufferString(`{"findings":[]}`)
		report, err := run.Execute(context.Background(), appdiagnose.Config{
			ControlsDir:     "ctl",
			ObservationsDir: "obs",
			OutputReader:    reader,
			MaxUnsafe:       30 * time.Minute,
			Clock:           clockadp.FixedClock{Time: now},
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

	t.Run("loads output from file", func(t *testing.T) {
		report, err := run.Execute(context.Background(), appdiagnose.Config{
			ControlsDir:     "ctl",
			ObservationsDir: "obs",
			OutputFile:      "out.json",
			MaxUnsafe:       30 * time.Minute,
			Clock:           clockadp.FixedClock{Time: now},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if report == nil {
			t.Fatal("expected report")
		}
	})
}

func TestDiagnoseExecute_EvaluationResultRepoErrors(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	errStub := evalResultRepoStub{err: errors.New("bad output")}
	run, newErr := appdiagnose.NewRun(
		evalObservationRepoStub{snapshots: []asset.Snapshot{{CapturedAt: now}}},
		evalControlRepoStub{controls: []policy.ControlDefinition{{ID: "CTL.TEST.001"}}},
		errStub,
		errStub,
	)
	if newErr != nil {
		t.Fatal(newErr)
	}

	_, err := run.Execute(context.Background(), appdiagnose.Config{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
		OutputReader:    bytes.NewBufferString(`{bad}`),
		MaxUnsafe:       time.Hour,
		Clock:           clockadp.FixedClock{Time: now},
	})
	if err == nil || !strings.Contains(err.Error(), "bad output") {
		t.Fatalf("unexpected err: %v", err)
	}
}
