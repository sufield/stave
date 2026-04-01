package diagnose

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
)

func TestPresenter_RenderReport_Template(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: diagnosis.ScenarioEmptyFindings, Signal: "signal1", Evidence: "ev1", Action: "act1"},
		},
		Summary: diagnosis.Summary{
			TotalSnapshots:  2,
			TotalAssets:     3,
			TotalControls:   5,
			ViolationsFound: 1,
		},
	}

	var buf bytes.Buffer
	p := &Presenter{
		W:        &buf,
		Format:   appcontracts.FormatText,
		Template: "Issues: {{len .Report.Issues}}",
	}
	err := p.RenderReport(report)
	if err != nil {
		t.Fatalf("RenderReport with template error: %v", err)
	}
	if !strings.Contains(buf.String(), "Issues: 1") {
		t.Fatalf("expected template output, got: %s", buf.String())
	}
}

func TestPresenter_RenderDetail_JSON(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:   "CTL.TEST.001",
			Name: "Test Control",
		},
		Asset: evaluation.FindingAssetSummary{
			ID:   asset.ID("test-asset"),
			Type: "test_type",
		},
		Evidence:  evaluation.Evidence{},
		NextSteps: []string{"step1", "step2"},
	}

	var buf bytes.Buffer
	p := &Presenter{W: &buf, Format: appcontracts.FormatJSON}
	err := p.RenderDetail(detail)
	if err != nil {
		t.Fatalf("RenderDetail JSON error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if _, ok := out["control"]; !ok {
		t.Fatal("expected 'control' in JSON output")
	}
	if _, ok := out["next_steps"]; !ok {
		t.Fatal("expected 'next_steps' in JSON output")
	}
}

func TestPresenter_RenderDetail_Text(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:   "CTL.TEST.001",
			Name: "Test Control",
		},
		Asset: evaluation.FindingAssetSummary{
			ID:   asset.ID("test-asset"),
			Type: "test_type",
		},
		Evidence:  evaluation.Evidence{},
		NextSteps: []string{"fix it"},
	}

	var buf bytes.Buffer
	p := &Presenter{W: &buf, Format: appcontracts.FormatText}
	err := p.RenderDetail(detail)
	if err != nil {
		t.Fatalf("RenderDetail text error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty text output")
	}
}

func TestJsonTrace_MarshalJSON_Nil(t *testing.T) {
	jt := jsonTrace{}
	data, err := jt.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != "null" {
		t.Fatalf("expected null, got %s", string(data))
	}
}

func TestJsonTrace_MarshalJSON_NilRaw(t *testing.T) {
	jt := jsonTrace{trace: &evaluation.FindingTrace{}}
	data, err := jt.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != "null" {
		t.Fatalf("expected null for nil Raw, got %s", string(data))
	}
}

func TestWriteFindingDetailJSON(t *testing.T) {
	detail := &evaluation.FindingDetail{
		Control: evaluation.FindingControlSummary{
			ID:   "CTL.TEST.001",
			Name: "Test Control",
		},
		Asset: evaluation.FindingAssetSummary{
			ID:   asset.ID("asset-1"),
			Type: "bucket",
		},
		NextSteps: []string{"fix the issue"},
	}

	var buf bytes.Buffer
	err := writeFindingDetailJSON(&buf, detail)
	if err != nil {
		t.Fatalf("writeFindingDetailJSON error: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := out["control"]; !ok {
		t.Fatal("missing control field")
	}
	if _, ok := out["asset"]; !ok {
		t.Fatal("missing asset field")
	}
}

func TestExplainRequest_EmptyControlID(t *testing.T) {
	e := &Explainer{Finder: nil}
	_, err := e.Run(t.Context(), ExplainRequest{ControlID: ""})
	if err == nil {
		t.Fatal("expected error for empty control ID")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDiagnoseOptions_Defaults(t *testing.T) {
	opts := &diagnoseOptions{}
	if opts.ControlsDir != "" {
		t.Fatalf("default ControlsDir should be empty, got %q", opts.ControlsDir)
	}
	if opts.Format != "" {
		t.Fatalf("default Format should be empty, got %q", opts.Format)
	}
}
