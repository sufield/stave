package domain

import (
	"encoding/json"
	"testing"
)

func TestDoctorRequest_JSON(t *testing.T) {
	req := DoctorRequest{Cwd: "/home/user/project", BinaryPath: "/usr/bin/stave", Format: "text"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got DoctorRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Cwd != req.Cwd {
		t.Errorf("Cwd: got %q, want %q", got.Cwd, req.Cwd)
	}
}

func TestDoctorResponse_JSON(t *testing.T) {
	resp := DoctorResponse{
		Checks:    []DoctorCheck{{Name: "git", Status: "pass", Message: "/usr/bin/git"}, {Name: "jq", Status: "warn", Message: "not found", Fix: "brew install jq"}},
		AllPassed: true,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got DoctorResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if len(got.Checks) != 2 {
		t.Errorf("Checks count: got %d, want 2", len(got.Checks))
	}
	if !got.AllPassed {
		t.Error("AllPassed: got false, want true")
	}
}

func TestConfigShowRequest_JSON(t *testing.T) {
	req := ConfigShowRequest{Format: "json"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ConfigShowRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Format != "json" {
		t.Errorf("Format: got %q, want %q", got.Format, "json")
	}
}

func TestConfigShowResponse_JSON(t *testing.T) {
	resp := ConfigShowResponse{ConfigData: map[string]any{"max_unsafe": "168h", "source": "stave.yaml"}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ConfigShowResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.ConfigData == nil {
		t.Error("ConfigData: got nil")
	}
}

func TestStatusRequest_JSON(t *testing.T) {
	req := StatusRequest{Dir: "/home/user/project"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got StatusRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Dir != "/home/user/project" {
		t.Errorf("Dir: got %q", got.Dir)
	}
}

func TestStatusResponse_JSON(t *testing.T) {
	resp := StatusResponse{
		StateData:   map[string]any{"has_controls": true, "has_observations": true},
		NextCommand: "stave apply",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got StatusResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.NextCommand != "stave apply" {
		t.Errorf("NextCommand: got %q", got.NextCommand)
	}
	if got.StateData == nil {
		t.Error("StateData: got nil")
	}
}

func TestGenerateControlRequest_JSON(t *testing.T) {
	req := GenerateControlRequest{Name: "No Public Read", OutPath: "controls/CTL.S3.PUBLIC.001.yaml"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got GenerateControlRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Name != "No Public Read" {
		t.Errorf("Name: got %q", got.Name)
	}
}

func TestGenerateControlResponse_JSON(t *testing.T) {
	resp := GenerateControlResponse{OutputPath: "controls/CTL.S3.PUBLIC.001.yaml"}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got GenerateControlResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.OutputPath != "controls/CTL.S3.PUBLIC.001.yaml" {
		t.Errorf("OutputPath: got %q", got.OutputPath)
	}
}

func TestBugReportRequest_JSON(t *testing.T) {
	req := BugReportRequest{OutPath: "/tmp/diag.zip", TailLines: 500, IncludeConfig: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got BugReportRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.OutPath != "/tmp/diag.zip" {
		t.Errorf("OutPath: got %q", got.OutPath)
	}
	if got.TailLines != 500 {
		t.Errorf("TailLines: got %d, want 500", got.TailLines)
	}
	if !got.IncludeConfig {
		t.Error("IncludeConfig: got false, want true")
	}
}

func TestBugReportResponse_JSON(t *testing.T) {
	resp := BugReportResponse{BundlePath: "/tmp/stave-diag.zip", Warnings: []string{"skipped config"}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got BugReportResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.BundlePath != "/tmp/stave-diag.zip" {
		t.Errorf("BundlePath: got %q", got.BundlePath)
	}
	if len(got.Warnings) != 1 || got.Warnings[0] != "skipped config" {
		t.Errorf("Warnings: got %v", got.Warnings)
	}
}

func TestInitProjectRequest_JSON(t *testing.T) {
	req := InitProjectRequest{
		Dir: "/home/user/project", Profile: "aws-s3", DryRun: true,
		WithGitHubActions: true, CaptureCadence: "hourly", Force: false,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InitProjectRequest
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.Dir != "/home/user/project" {
		t.Errorf("Dir: got %q", got.Dir)
	}
	if got.Profile != "aws-s3" {
		t.Errorf("Profile: got %q", got.Profile)
	}
	if !got.DryRun {
		t.Error("DryRun: got false, want true")
	}
	if !got.WithGitHubActions {
		t.Error("WithGitHubActions: got false, want true")
	}
	if got.CaptureCadence != "hourly" {
		t.Errorf("CaptureCadence: got %q", got.CaptureCadence)
	}
}

func TestInitProjectResponse_JSON(t *testing.T) {
	resp := InitProjectResponse{
		BaseDir: "/home/user/project",
		Dirs:    []string{"controls", "observations"},
		Created: []string{"stave.yaml", ".gitignore"},
		Skipped: []string{"controls/README.md"},
		DryRun:  false,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got InitProjectResponse
	if unmarshalErr := json.Unmarshal(data, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal: %v", unmarshalErr)
	}
	if got.BaseDir != "/home/user/project" {
		t.Errorf("BaseDir: got %q", got.BaseDir)
	}
	if len(got.Created) != 2 {
		t.Errorf("Created count: got %d, want 2", len(got.Created))
	}
	if len(got.Skipped) != 1 {
		t.Errorf("Skipped count: got %d, want 1", len(got.Skipped))
	}
}
