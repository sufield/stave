package domain

import (
	"encoding/json"
	"testing"
)

func TestControlsListRequest_JSON(t *testing.T) {
	req := ControlsListRequest{
		ControlsDir: "controls/s3",
		BuiltIn:     true,
		Columns:     "id,name,severity",
		SortBy:      "severity",
		Filter:      []string{"severity:high+"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ControlsListRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if !got.BuiltIn {
		t.Error("BuiltIn: got false, want true")
	}
	if len(got.Filter) != 1 {
		t.Errorf("Filter count: got %d, want 1", len(got.Filter))
	}
}

func TestControlsListResponse_JSON(t *testing.T) {
	resp := ControlsListResponse{
		Controls: []ControlRow{
			{ID: "CTL.S3.PUBLIC.001", Name: "No Public Read", Type: "unsafe_duration", Severity: "critical"},
			{ID: "CTL.S3.ENCRYPT.001", Name: "SSE Enabled", Type: "unsafe_state", Severity: "high"},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ControlsListResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if len(got.Controls) != 2 {
		t.Errorf("Controls count: got %d, want 2", len(got.Controls))
	}
	if got.Controls[0].ID != "CTL.S3.PUBLIC.001" {
		t.Errorf("Controls[0].ID: got %q", got.Controls[0].ID)
	}
}

func TestGraphCoverageRequest_JSON(t *testing.T) {
	req := GraphCoverageRequest{ControlsDir: "controls/s3", ObservationsDir: "observations"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got GraphCoverageRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ControlsDir != "controls/s3" {
		t.Errorf("ControlsDir: got %q", got.ControlsDir)
	}
}

func TestGraphCoverageResponse_JSON(t *testing.T) {
	resp := GraphCoverageResponse{GraphData: map[string]any{"edges": 5}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got GraphCoverageResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.GraphData == nil {
		t.Error("GraphData: got nil")
	}
}
