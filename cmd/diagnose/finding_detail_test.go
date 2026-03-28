package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	clockadp "github.com/sufield/stave/pkg/alpha/domain/ports"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

func TestRunnerDetailMode_ValidationShortCircuit(t *testing.T) {
	p := compose.NewDefaultProvider()
	obsRepo, _ := p.NewObservationRepo()
	ctlRepo, _ := p.NewControlRepo()
	runner := NewRunner(obsRepo, ctlRepo, clockadp.RealClock{})
	cfg := Config{
		ControlID:         "",
		AssetID:           "res-1",
		MaxUnsafeDuration: 24 * time.Hour,
		Format:            ui.OutputFormatText,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
	}
	err := runner.Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "detail mode requires both") {
		t.Fatalf("expected detail mode validation error, got %v", err)
	}
}

func TestPresenterRenderDetail_IncludesTrace(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control:  evaluation.FindingControlSummary{ID: "CTL.TEST.A.001", Name: "A"},
		Asset:    evaluation.FindingAssetSummary{ID: "res-1", Type: "storage_bucket"},
		Evidence: evaluation.Evidence{},
		Trace: &evaluation.FindingTrace{
			Raw: &stavecel.TraceResult{
				ControlID:  kernel.ControlID("CTL.TEST.A.001"),
				AssetID:    "res-1",
				Expression: `any(properties.k == "v")`,
				Result:     true,
			},
			FinalResult: true,
		},
		NextSteps: []string{"step"},
	}

	var buf bytes.Buffer
	p := &Presenter{W: &buf, Format: ui.OutputFormatJSON}
	if err := p.RenderDetail(detail); err != nil {
		t.Fatalf("RenderDetail() error = %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal detail json: %v", err)
	}
	if _, ok := out["trace"]; !ok {
		t.Fatalf("expected trace field, got keys %v", out)
	}
}

func TestRunnerDetailMode_SuccessJSON(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		{
			ID:          "CTL.TEST.A.001",
			Name:        "Control A",
			Description: "desc",
			Type:        policy.TypeUnsafeDuration,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
	}
	snapshots := []asset.Snapshot{
		{
			CapturedAt: now,
			Assets: []asset.Asset{
				{
					ID:     "res-1",
					Type:   kernel.AssetType("storage_bucket"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"public": true,
					},
				},
			},
		},
	}
	result := &evaluation.Result{
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.TEST.A.001",
				ControlName:        "Control A",
				ControlDescription: "desc",
				AssetID:            "res-1",
				AssetType:          kernel.AssetType("storage_bucket"),
				AssetVendor:        kernel.Vendor("aws"),
				Evidence:           evaluation.Evidence{LastSeenUnsafeAt: now},
			},
		},
	}

	// Write eval result to temp file for the real JSON loader.
	tmp := t.TempDir()
	evalFile := filepath.Join(tmp, "eval.json")
	evalJSON, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if writeErr := os.WriteFile(evalFile, evalJSON, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}

	var out bytes.Buffer
	runner := NewRunner(
		diagnoseObsRepoStub{snapshots: snapshots},
		diagnoseInvRepoStub{controls: controls},
		clockadp.FixedClock(now),
	)
	cfg := Config{
		ControlsDir:       "ctl",
		ObservationsDir:   "obs",
		PreviousOutput:    evalFile,
		MaxUnsafeDuration: time.Hour,
		Format:            ui.OutputFormatJSON,
		ControlID:         "CTL.TEST.A.001",
		AssetID:           "res-1",
		Stdout:            &out,
		Stderr:            &bytes.Buffer{},
	}

	if runErr := runner.Run(context.Background(), cfg); runErr != nil {
		t.Fatalf("expected nil in json mode, got %v", runErr)
	}
	if !strings.Contains(out.String(), "\"control\"") {
		t.Fatalf("expected finding detail json output, got %s", out.String())
	}

	// Text mode branch returns ErrViolationsFound.
	out.Reset()
	cfg.Format = ui.OutputFormatText
	if runErr := runner.Run(context.Background(), cfg); runErr != ui.ErrViolationsFound {
		t.Fatalf("expected ErrViolationsFound in text mode, got %v", runErr)
	}
}
