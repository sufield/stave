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
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	clockadp "github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/trace"
)

func TestValidateFindingDetailArgs(t *testing.T) {
	if err := validateFindingDetailArgs("", "res-1"); err == nil {
		t.Fatal("expected control-id error")
	}
	if err := validateFindingDetailArgs("CTL.TEST.A.001", ""); err == nil {
		t.Fatal("expected resource-id error")
	}
	if err := validateFindingDetailArgs("CTL.TEST.A.001", "res-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunnerDetailMode_ValidationShortCircuit(t *testing.T) {
	runner := NewRunner(compose.NewDefaultProvider(), clockadp.RealClock{})
	cfg := Config{
		ControlID: "",
		AssetID:   "res-1",
		MaxUnsafe: "24h",
		Format:    ui.OutputFormatText,
		Stdout:    &bytes.Buffer{},
		Stderr:    &bytes.Buffer{},
	}
	err := runner.Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "detail mode requires both") {
		t.Fatalf("expected detail mode validation error, got %v", err)
	}
}

func TestWriteFindingDetailJSON_IncludesTrace(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control:  evaluation.FindingControlSummary{ID: "CTL.TEST.A.001", Name: "A"},
		Asset:    evaluation.FindingAssetSummary{ID: "res-1", Type: "storage_bucket"},
		Evidence: evaluation.Evidence{},
		Trace: &evaluation.FindingTrace{
			Raw: &trace.TraceResult{
				ControlID:  "CTL.TEST.A.001",
				AssetID:    "res-1",
				Properties: map[string]any{"k": "v"},
				Root: &trace.GroupNode{
					Logic:             trace.LogicAny,
					ShortCircuitIndex: -1,
					Result:            true,
					Children: []trace.Node{
						&trace.ClauseNode{Index: 0, Field: "properties.k", Op: "eq", Value: "v", Result: true},
					},
				},
				FinalResult: true,
			},
			FinalResult: true,
		},
		NextSteps: []string{"step"},
	}

	var buf bytes.Buffer
	if err := writeFindingDetailJSON(&buf, detail); err != nil {
		t.Fatalf("writeFindingDetailJSON() error = %v", err)
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
					{Field: "properties.public", Op: "eq", Value: true},
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

	provider := &compose.Provider{
		ObsRepoFunc: func() (appcontracts.ObservationRepository, error) {
			return diagnoseObsRepoStub{snapshots: snapshots}, nil
		},
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) {
			return diagnoseInvRepoStub{controls: controls}, nil
		},
	}

	var out bytes.Buffer
	runner := NewRunner(provider, clockadp.FixedClock(now))
	cfg := Config{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
		PreviousOutput:  evalFile,
		MaxUnsafe:       "1h",
		Format:          ui.OutputFormatJSON,
		ControlID:       "CTL.TEST.A.001",
		AssetID:         "res-1",
		Stdout:          &out,
		Stderr:          &bytes.Buffer{},
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
