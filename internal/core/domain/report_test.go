package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBaselineSaveRequest_JSON(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		req  BaselineSaveRequest
	}{
		{
			name: "required fields only",
			req:  BaselineSaveRequest{EvaluationPath: "output/evaluation.json", OutputPath: "output/baseline.json"},
		},
		{
			name: "all fields",
			req:  BaselineSaveRequest{EvaluationPath: "output/evaluation.json", OutputPath: "output/baseline.json", Now: &now, Sanitize: true, Force: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got BaselineSaveRequest
			if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
				t.Fatalf("unmarshal: %v", unmarshalErr)
			}
			redata, _ := json.Marshal(got)
			if string(data) != string(redata) {
				t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", redata, data)
			}
		})
	}
}

func TestBaselineCheckRequest_JSON(t *testing.T) {
	req := BaselineCheckRequest{EvaluationPath: "eval.json", BaselinePath: "baseline.json", FailOnNew: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got BaselineCheckRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FailOnNew != true {
		t.Error("FailOnNew: got false, want true")
	}
}

func TestBaselineSaveResponse_JSON(t *testing.T) {
	resp := BaselineSaveResponse{OutputPath: "output/baseline.json", FindingsCount: 5, CreatedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got BaselineSaveResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FindingsCount != 5 {
		t.Errorf("FindingsCount: got %d, want 5", got.FindingsCount)
	}
}

func TestBaselineCheckResponse_JSON(t *testing.T) {
	resp := BaselineCheckResponse{
		BaselineFile: "baseline.json", Evaluation: "eval.json",
		CheckedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Summary:   BaselineCheckSummary{BaselineFindings: 3, CurrentFindings: 4, NewFindings: 2, ResolvedFindings: 1},
		NewFindings: []BaselineFinding{
			{ControlID: "CTL.A", ControlName: "A", AssetID: "res-1", AssetType: "bucket"},
			{ControlID: "CTL.B", ControlName: "B", AssetID: "res-2", AssetType: "bucket"},
		},
		ResolvedFindings: []BaselineFinding{{ControlID: "CTL.C", ControlName: "C", AssetID: "res-3", AssetType: "bucket"}},
		HasNew:           true,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got BaselineCheckResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Summary.NewFindings != 2 {
		t.Errorf("Summary.NewFindings: got %d, want 2", got.Summary.NewFindings)
	}
	if !got.HasNew {
		t.Error("HasNew: got false, want true")
	}
}

func TestCIDiffRequest_JSON(t *testing.T) {
	req := CIDiffRequest{CurrentPath: "current.json", BaselinePath: "baseline.json", FailOnNew: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got CIDiffRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.CurrentPath != "current.json" {
		t.Errorf("CurrentPath: got %q", got.CurrentPath)
	}
}

func TestCIDiffResponse_JSON(t *testing.T) {
	resp := CIDiffResponse{
		CurrentEvaluation: "current.json", BaselineEvaluation: "baseline.json",
		ComparedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Summary:    CIDiffSummary{BaselineFindings: 3, CurrentFindings: 4, NewFindings: 2, ResolvedFindings: 1},
		NewFindings: []BaselineFinding{
			{ControlID: "CTL.A", AssetID: "res-1"},
			{ControlID: "CTL.B", AssetID: "res-2"},
		},
		HasNew: true,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got CIDiffResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Summary.NewFindings != 2 {
		t.Errorf("Summary.NewFindings: got %d, want 2", got.Summary.NewFindings)
	}
}

func TestReportRequest_JSON(t *testing.T) {
	req := ReportRequest{InputFile: "eval.json", Format: "json"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ReportRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.InputFile != "eval.json" {
		t.Errorf("InputFile: got %q", got.InputFile)
	}
}

func TestReportResponse_JSON(t *testing.T) {
	resp := ReportResponse{EvaluationData: map[string]any{"summary": map[string]any{"violations": 3}}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ReportResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.EvaluationData == nil {
		t.Error("EvaluationData: got nil")
	}
}

func TestExplainRequest_JSON(t *testing.T) {
	req := ExplainRequest{ControlID: "CTL.S3.PUBLIC.001", ControlsDir: "controls/s3"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ExplainRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("ControlID: got %q", got.ControlID)
	}
}

func TestExplainResponse_JSON(t *testing.T) {
	resp := ExplainResponse{
		ControlID:     "CTL.S3.PUBLIC.001",
		Name:          "No Public Read",
		Description:   "S3 buckets must not allow public read",
		Type:          "unsafe_duration",
		MatchedFields: []string{"properties.storage.access.public_read"},
		Rules: []ExplainRule{
			{Path: "properties.storage.access.public_read", Op: "eq", Value: true, From: "all[0]"},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ExplainResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("ControlID: got %q", got.ControlID)
	}
	if len(got.Rules) != 1 {
		t.Errorf("Rules count: got %d, want 1", len(got.Rules))
	}
}

func TestDiagnoseRequest_JSON(t *testing.T) {
	req := DiagnoseRequest{
		ControlsDir:     "controls",
		ObservationsDir: "observations",
		CaseFilter:      []string{"duration"},
		ControlID:       "CTL.S3.PUBLIC.001",
		AssetID:         "bucket-a",
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got DiagnoseRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ControlsDir != "controls" {
		t.Errorf("ControlsDir: got %q", got.ControlsDir)
	}
	if got.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("ControlID: got %q", got.ControlID)
	}
}

func TestDiagnoseResponse_JSON(t *testing.T) {
	resp := DiagnoseResponse{
		ReportData:   map[string]any{"issues": []any{"finding-1"}},
		IsDetailMode: true,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got DiagnoseResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if !got.IsDetailMode {
		t.Error("IsDetailMode: got false, want true")
	}
	if got.ReportData == nil {
		t.Error("ReportData: got nil")
	}
}

func TestEnforceRequest_JSON(t *testing.T) {
	req := EnforceRequest{InputPath: "eval.json", OutDir: "output", Mode: "pab", DryRun: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got EnforceRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Mode != "pab" {
		t.Errorf("Mode: got %q", got.Mode)
	}
	if !got.DryRun {
		t.Error("DryRun: got false, want true")
	}
}

func TestEnforceResponse_JSON(t *testing.T) {
	resp := EnforceResponse{OutputFile: "output/enforcement/aws/pab.tf", Targets: []string{"bucket-a", "bucket-b"}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got EnforceResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if len(got.Targets) != 2 {
		t.Errorf("Targets count: got %d, want 2", len(got.Targets))
	}
	if got.OutputFile != "output/enforcement/aws/pab.tf" {
		t.Errorf("OutputFile: got %q", got.OutputFile)
	}
}
