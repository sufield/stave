package domain

import (
	"encoding/json"
	"testing"
)

func TestSecurityAuditRequest_JSON(t *testing.T) {
	req := SecurityAuditRequest{
		Format:               "json",
		FailOn:               "HIGH",
		Severities:           []string{"CRITICAL", "HIGH"},
		ComplianceFrameworks: []string{"CIS"},
		LiveVulnCheck:        true,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SecurityAuditRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FailOn != "HIGH" {
		t.Errorf("FailOn: got %q", got.FailOn)
	}
	if !got.LiveVulnCheck {
		t.Error("LiveVulnCheck: got false, want true")
	}
	if len(got.Severities) != 2 {
		t.Errorf("Severities count: got %d, want 2", len(got.Severities))
	}
}

func TestSecurityAuditResponse_JSON(t *testing.T) {
	resp := SecurityAuditResponse{
		ReportData: map[string]any{"findings": 3},
		Summary:    SecurityAuditSummary{Total: 10, Pass: 7, Warn: 1, Fail: 2, Threshold: "HIGH"},
		Gated:      true,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got SecurityAuditResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if !got.Gated {
		t.Error("Gated: got false, want true")
	}
	if got.Summary.Total != 10 {
		t.Errorf("Summary.Total: got %d, want 10", got.Summary.Total)
	}
	if got.Summary.Fail != 2 {
		t.Errorf("Summary.Fail: got %d, want 2", got.Summary.Fail)
	}
}

func TestInspectPolicyRequest_JSON(t *testing.T) {
	req := InspectPolicyRequest{FilePath: "policy.json"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectPolicyRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FilePath != "policy.json" {
		t.Errorf("FilePath: got %q", got.FilePath)
	}
}

func TestInspectPolicyResponse_JSON(t *testing.T) {
	resp := InspectPolicyResponse{
		Assessment:  map[string]any{"public": true},
		PrefixScope: map[string]any{"scopes": 2},
		Risk:        map[string]any{"level": "HIGH"},
		RequiredIAM: []string{"s3:GetObject", "s3:ListBucket"},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectPolicyResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Assessment == nil {
		t.Error("Assessment: got nil")
	}
	if len(got.RequiredIAM) != 2 {
		t.Errorf("RequiredIAM count: got %d, want 2", len(got.RequiredIAM))
	}
}

func TestInspectACLRequest_JSON(t *testing.T) {
	req := InspectACLRequest{FilePath: "grants.json"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectACLRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FilePath != "grants.json" {
		t.Errorf("FilePath: got %q", got.FilePath)
	}
}

func TestInspectACLResponse_JSON(t *testing.T) {
	resp := InspectACLResponse{
		Assessment:   map[string]any{"has_public": true, "grant_count": 3},
		GrantDetails: []any{map[string]any{"grantee": "AllUsers", "is_public": true}},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectACLResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Assessment == nil {
		t.Error("Assessment: got nil")
	}
	if got.GrantDetails == nil {
		t.Error("GrantDetails: got nil")
	}
}
