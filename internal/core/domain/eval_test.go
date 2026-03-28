package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestGateRequest_JSON(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	req := GateRequest{Policy: "fail_on_any_violation", EvaluationPath: "eval.json", MaxUnsafeDuration: 72 * time.Hour, Now: &now}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got GateRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Policy != req.Policy {
		t.Errorf("Policy: got %q, want %q", got.Policy, req.Policy)
	}
}

func TestGateResponse_JSON(t *testing.T) {
	resp := GateResponse{Policy: "fail_on_any_violation", Passed: false, Reason: "current findings=3", CheckedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC), CurrentViolations: 3}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got GateResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Passed {
		t.Error("Passed: got true, want false")
	}
}

func TestFixRequest_JSON(t *testing.T) {
	req := FixRequest{InputPath: "eval.json", FindingRef: "CTL.S3.PUBLIC.001@bucket-a"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got FixRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FindingRef != req.FindingRef {
		t.Errorf("FindingRef: got %q, want %q", got.FindingRef, req.FindingRef)
	}
}

func TestFixResponse_JSON(t *testing.T) {
	resp := FixResponse{Data: map[string]any{"control_id": "CTL.A", "fix_plan": map[string]any{"id": "fix-123"}}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got FixResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Data == nil {
		t.Error("Data: got nil")
	}
}

func TestTraceRequest_JSON(t *testing.T) {
	req := TraceRequest{ControlID: "CTL.S3.PUBLIC.001", ControlsDir: "controls", ObservationPath: "obs.json", AssetID: "bucket-a"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got TraceRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("ControlID: got %q", got.ControlID)
	}
	if got.AssetID != "bucket-a" {
		t.Errorf("AssetID: got %q", got.AssetID)
	}
}

func TestTraceResponse_JSON(t *testing.T) {
	resp := TraceResponse{TraceData: map[string]any{"clauses": 3, "result": "UNSAFE"}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got TraceResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.TraceData == nil {
		t.Error("TraceData: got nil")
	}
}
