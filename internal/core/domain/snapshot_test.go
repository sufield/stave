package domain

import (
	"encoding/json"
	"testing"
)

func TestSnapshotDiffRequest_JSON(t *testing.T) {
	req := SnapshotDiffRequest{ObservationsDir: "observations", ChangeTypes: []string{"added", "removed"}, AssetTypes: []string{"aws_s3_bucket"}, AssetID: "bucket"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SnapshotDiffRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ObservationsDir != "observations" {
		t.Errorf("ObservationsDir: got %q", got.ObservationsDir)
	}
	if len(got.ChangeTypes) != 2 {
		t.Errorf("ChangeTypes: got %d, want 2", len(got.ChangeTypes))
	}
}

func TestSnapshotDiffResponse_JSON(t *testing.T) {
	resp := SnapshotDiffResponse{DeltaData: map[string]any{"changes": []any{"added-bucket"}}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SnapshotDiffResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.DeltaData == nil {
		t.Error("DeltaData: got nil")
	}
}

func TestSnapshotUpcomingRequest_JSON(t *testing.T) {
	req := SnapshotUpcomingRequest{
		ControlsDir:     "controls",
		ObservationsDir: "observations",
		DueSoon:         "24h",
		StatusFilter:    []string{"OVERDUE", "DUE_NOW"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SnapshotUpcomingRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.DueSoon != "24h" {
		t.Errorf("DueSoon: got %q", got.DueSoon)
	}
	if len(got.StatusFilter) != 2 {
		t.Errorf("StatusFilter count: got %d, want 2", len(got.StatusFilter))
	}
}

func TestSnapshotUpcomingResponse_JSON(t *testing.T) {
	resp := SnapshotUpcomingResponse{ItemsData: map[string]any{"count": 3}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SnapshotUpcomingResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ItemsData == nil {
		t.Error("ItemsData: got nil")
	}
}
