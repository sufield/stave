package eval

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	s3 "github.com/sufield/stave/internal/adapters/aws/s3"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	clockadp "github.com/sufield/stave/pkg/alpha/domain/ports"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

type evalControlRepoStub struct {
	controls []policy.ControlDefinition
	err      error
}

func (s evalControlRepoStub) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return s.controls, s.err
}

type evalObservationRepoStub struct {
	snapshots []asset.Snapshot
	err       error
	hashes    *evaluation.InputHashes
}

func (s evalObservationRepoStub) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{Snapshots: s.snapshots, Hashes: s.hashes}, s.err
}

type marshalerStub struct {
	err          error
	marshalCalls int
	lastEnriched appcontracts.EnrichedResult
}

func (s *marshalerStub) MarshalFindings(enriched appcontracts.EnrichedResult) ([]byte, error) {
	s.marshalCalls++
	s.lastEnriched = enriched
	if s.err != nil {
		return nil, s.err
	}
	return []byte(`{"ok":true}`), nil
}

func testEnrichFn(result evaluation.Result) appcontracts.EnrichedResult {
	return appcontracts.EnrichedResult{
		Result:         result,
		Findings:       []remediation.Finding{},
		ExemptedAssets: result.ExemptedAssets,
		Run:            result.Run,
	}
}

func TestLoadControls(t *testing.T) {
	t.Run("repo error", func(t *testing.T) {
		_, err := appcontracts.LoadControls(context.Background(), evalControlRepoStub{err: errors.New("boom")}, "ctl")
		if err == nil || !strings.Contains(err.Error(), "failed to load controls") {
			t.Fatalf("unexpected err: %v", err)
		}
	})
}

func TestLoadSnapshots(t *testing.T) {
	t.Run("repo error", func(t *testing.T) {
		_, err := appcontracts.LoadSnapshots(context.Background(), evalObservationRepoStub{err: errors.New("boom")}, "obs")
		if err == nil || !strings.Contains(err.Error(), "failed to load observations") {
			t.Fatalf("unexpected err: %v", err)
		}
	})
}

func TestEvaluateRunExecute(t *testing.T) {
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
	_ = ctl.Prepare()
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

	t.Run("writes findings and returns violations", func(t *testing.T) {
		m := &marshalerStub{}
		run := NewEvaluateRun(
			evalObservationRepoStub{
				snapshots: snapshots,
				hashes: &evaluation.InputHashes{
					Files:   map[evaluation.FilePath]kernel.Digest{"a.json": "abc"},
					Overall: "overall",
				},
			},
			evalControlRepoStub{controls: []policy.ControlDefinition{ctl}},
			m,
			testEnrichFn,
		)

		status, err := run.Execute(context.Background(), EvaluateConfig{
			LoadConfig: LoadConfig{
				ControlsDir:     "ctl",
				ObservationsDir: "obs",
			},
			MaxUnsafe:    30 * time.Minute,
			Clock:        clockadp.FixedClock(now),
			Output:       &bytes.Buffer{},
			CELEvaluator: mustPredicateEval(),
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if status == evaluation.StatusSafe {
			t.Fatal("expected non-safe status")
		}
		if m.marshalCalls != 1 {
			t.Fatalf("marshal calls=%d, want 1", m.marshalCalls)
		}
		if len(m.lastEnriched.Result.Findings) == 0 {
			t.Fatal("expected at least one finding")
		}
		if m.lastEnriched.Run.InputHashes == nil || m.lastEnriched.Run.InputHashes.Overall != "overall" {
			t.Fatalf("expected input hashes to flow through, got %#v", m.lastEnriched.Run.InputHashes)
		}
	})

	t.Run("marshaler failure is wrapped", func(t *testing.T) {
		run := NewEvaluateRun(
			evalObservationRepoStub{snapshots: snapshots},
			evalControlRepoStub{controls: []policy.ControlDefinition{ctl}},
			&marshalerStub{err: errors.New("marshal boom")},
			testEnrichFn,
		)

		_, err := run.Execute(context.Background(), EvaluateConfig{
			LoadConfig: LoadConfig{
				ControlsDir:     "ctl",
				ObservationsDir: "obs",
			},
			MaxUnsafe:    30 * time.Minute,
			Clock:        clockadp.FixedClock(now),
			Output:       &bytes.Buffer{},
			CELEvaluator: mustPredicateEval(),
		})
		if err == nil || !strings.Contains(err.Error(), "failed to write findings") {
			t.Fatalf("unexpected err: %v", err)
		}
	})
}
