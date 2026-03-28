package domain

import (
	"encoding/json"
	"testing"
)

func TestValidateRequest_JSON(t *testing.T) {
	req := ValidateRequest{ControlsDir: "controls", ObservationsDir: "observations", Strict: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ValidateRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if !got.Strict {
		t.Error("Strict: got false, want true")
	}
}

func TestValidateResponse_JSON(t *testing.T) {
	resp := ValidateResponse{
		Valid:    false,
		Errors:   []ValidateDiagnostic{{Code: "SCHEMA_001", Message: "invalid field", Path: "controls/test.yaml"}},
		Warnings: []ValidateDiagnostic{{Message: "deprecated field"}},
		Summary:  ValidateSummary{ControlsChecked: 5, ObservationsChecked: 3},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ValidateResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Valid {
		t.Error("Valid: got true, want false")
	}
	if got.Summary.ControlsChecked != 5 {
		t.Errorf("ControlsChecked: got %d, want 5", got.Summary.ControlsChecked)
	}
}

func TestLintRequest_JSON(t *testing.T) {
	req := LintRequest{Target: "controls/s3"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got LintRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Target != "controls/s3" {
		t.Errorf("Target: got %q, want %q", got.Target, "controls/s3")
	}
}

func TestLintResponse_JSON(t *testing.T) {
	resp := LintResponse{
		Diagnostics: []LintDiagnostic{
			{Path: "ctl.yaml", Line: 10, Col: 5, RuleID: "CTL_ID_NAMESPACE", Message: "bad id", Severity: "error"},
			{Path: "ctl.yaml", Line: 15, Col: 3, RuleID: "CTL_ORDERING_HINT", Message: "unordered", Severity: "warn"},
		},
		ErrorCount: 1,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got LintResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if len(got.Diagnostics) != 2 {
		t.Errorf("Diagnostics count: got %d, want 2", len(got.Diagnostics))
	}
	if got.ErrorCount != 1 {
		t.Errorf("ErrorCount: got %d, want 1", got.ErrorCount)
	}
}

func TestFmtRequest_JSON(t *testing.T) {
	req := FmtRequest{Target: "controls/s3", CheckOnly: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got FmtRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Target != "controls/s3" {
		t.Errorf("Target: got %q", got.Target)
	}
	if !got.CheckOnly {
		t.Error("CheckOnly: got false, want true")
	}
}

func TestFmtResponse_JSON(t *testing.T) {
	resp := FmtResponse{FilesProcessed: 10, FilesChanged: 3}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got FmtResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FilesProcessed != 10 {
		t.Errorf("FilesProcessed: got %d, want 10", got.FilesProcessed)
	}
	if got.FilesChanged != 3 {
		t.Errorf("FilesChanged: got %d, want 3", got.FilesChanged)
	}
}
