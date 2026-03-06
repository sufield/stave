package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
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

func TestRunDiagnoseFindingDetail_ValidationShortCircuit(t *testing.T) {
	err := runDiagnoseFindingDetail(diagnoseFindingDetailRequest{
		cmd:         &cobra.Command{},
		diagnoseRun: nil,
		ctx:         nil,
		baseCfg:     appdiagnose.Config{},
		controlID:   "",
		assetID:     "res-1",
		formatRaw:   "text",
		quiet:       false,
	})
	if err == nil || !strings.Contains(err.Error(), "--control-id is required") {
		t.Fatalf("expected control-id error, got %v", err)
	}
}

func TestWriteFindingDetailJSON_IncludesTrace(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control:  evaluation.FindingControlSummary{ID: "CTL.TEST.A.001", Name: "A"},
		Resource: evaluation.FindingResourceSummary{ID: "res-1", Type: "storage_bucket"},
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

func TestRunDiagnoseFindingDetail_SuccessJSON(t *testing.T) {
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
			Resources: []asset.Asset{
				{
					ID:     "res-1",
					Type:   kernel.TypeStorageBucket,
					Vendor: kernel.VendorAWS,
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
				AssetType:          kernel.TypeStorageBucket,
				AssetVendor:        kernel.VendorAWS,
				Evidence:           evaluation.Evidence{LastSeenUnsafeAt: now},
			},
		},
	}

	evalStub := diagnoseEvalRepoStub{result: result}
	run := appdiagnose.NewRun(
		diagnoseObsRepoStub{snapshots: snapshots},
		diagnoseInvRepoStub{controls: controls},
		evalStub,
		evalStub,
	)

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("format", "text", "")
	_ = cmd.Flags().Set("format", "json")

	var out bytes.Buffer
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		_ = w.Close()
		_ = r.Close()
		os.Stdout = origStdout
	}()

	err = runDiagnoseFindingDetail(diagnoseFindingDetailRequest{
		cmd:         cmd,
		diagnoseRun: run,
		ctx:         context.Background(),
		baseCfg: appdiagnose.Config{
			ControlsDir:     "ctl",
			ObservationsDir: "obs",
			OutputFile:      "previous.json",
			MaxUnsafe:       time.Hour,
			Clock:           clockadp.FixedClock{Time: now},
		},
		controlID: "CTL.TEST.A.001",
		assetID:   "res-1",
		formatRaw: "json",
		quiet:     false,
	})
	if err != nil {
		t.Fatalf("expected nil in json mode, got %v", err)
	}

	_ = w.Close()
	if _, copyErr := io.Copy(&out, r); copyErr != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\"control\"") {
		t.Fatalf("expected finding detail json output, got %s", out.String())
	}

	// Text mode branch returns ErrViolationsFound.
	cmdText := &cobra.Command{Use: "test-text"}
	cmdText.Flags().String("format", "text", "")
	_ = cmdText.Flags().Set("format", "text")
	err = runDiagnoseFindingDetail(diagnoseFindingDetailRequest{
		cmd:         cmdText,
		diagnoseRun: run,
		ctx:         context.Background(),
		baseCfg: appdiagnose.Config{
			ControlsDir:     "ctl",
			ObservationsDir: "obs",
			OutputFile:      "previous.json",
			MaxUnsafe:       time.Hour,
			Clock:           clockadp.FixedClock{Time: now},
		},
		controlID: "CTL.TEST.A.001",
		assetID:   "res-1",
		formatRaw: "text",
		quiet:     true,
	})
	if err != ui.ErrViolationsFound {
		t.Fatalf("expected ErrViolationsFound in text mode, got %v", err)
	}
}
