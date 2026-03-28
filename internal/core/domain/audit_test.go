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

func TestInspectExposureRequest_JSON(t *testing.T) {
	req := InspectExposureRequest{FilePath: "resources.json"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectExposureRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FilePath != "resources.json" {
		t.Errorf("FilePath: got %q", got.FilePath)
	}
}

func TestInspectExposureResponse_JSON(t *testing.T) {
	resp := InspectExposureResponse{
		Classifications: []any{map[string]any{"name": "bucket-a", "exposure": "PUBLIC"}},
		BucketAccess:    map[string]any{"public_read": true},
		Visibility:      map[string]any{"effective": "public"},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectExposureResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Classifications == nil {
		t.Error("Classifications: got nil")
	}
	if got.BucketAccess == nil {
		t.Error("BucketAccess: got nil")
	}
}

func TestInspectRiskRequest_JSON(t *testing.T) {
	req := InspectRiskRequest{FilePath: "statement.json"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectRiskRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FilePath != "statement.json" {
		t.Errorf("FilePath: got %q", got.FilePath)
	}
}

func TestInspectRiskResponse_JSON(t *testing.T) {
	resp := InspectRiskResponse{
		NormalizedActions: []string{"s3:GetObject", "s3:PutObject"},
		Permissions:       map[string]any{"read": true, "write": true},
		PermissionCheck:   map[string]any{"has_read": true},
		StatementResult:   map[string]any{"score": 7},
		Report:            map[string]any{"level": "HIGH"},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectRiskResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if len(got.NormalizedActions) != 2 {
		t.Errorf("NormalizedActions count: got %d, want 2", len(got.NormalizedActions))
	}
	if got.Report == nil {
		t.Error("Report: got nil")
	}
}

func TestInspectComplianceRequest_JSON(t *testing.T) {
	req := InspectComplianceRequest{
		FilePath:   "crosswalk.yaml",
		Frameworks: []string{"nist_800_53", "cis"},
		CheckIDs:   []string{"CTL.S3.PUBLIC.001"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectComplianceRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.FilePath != "crosswalk.yaml" {
		t.Errorf("FilePath: got %q", got.FilePath)
	}
	if len(got.Frameworks) != 2 {
		t.Errorf("Frameworks count: got %d, want 2", len(got.Frameworks))
	}
	if len(got.CheckIDs) != 1 {
		t.Errorf("CheckIDs count: got %d, want 1", len(got.CheckIDs))
	}
}

func TestInspectComplianceResponse_JSON(t *testing.T) {
	resp := InspectComplianceResponse{ResolutionJSON: []byte(`{"resolved":true}`)}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectComplianceResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if len(got.ResolutionJSON) == 0 {
		t.Error("ResolutionJSON: got empty")
	}
}

func TestInspectAliasesRequest_JSON(t *testing.T) {
	req := InspectAliasesRequest{Category: "Encryption"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectAliasesRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Category != "Encryption" {
		t.Errorf("Category: got %q", got.Category)
	}
}

func TestInspectAliasesResponse_JSON(t *testing.T) {
	resp := InspectAliasesResponse{
		Aliases:            []any{map[string]any{"name": "is_encrypted", "category": "Encryption"}},
		SupportedOperators: []string{"eq", "ne", "in"},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InspectAliasesResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Aliases == nil {
		t.Error("Aliases: got nil")
	}
	if len(got.SupportedOperators) != 3 {
		t.Errorf("SupportedOperators count: got %d, want 3", len(got.SupportedOperators))
	}
}
