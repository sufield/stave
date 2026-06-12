package applycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod)")
		}
		dir = parent
	}
}

func TestValidateInput_NotFound(t *testing.T) {
	err := validateInput("/nonexistent/path/to/file.json")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got: %v", err)
	}
}

func TestValidateInput_IsDirectory(t *testing.T) {
	err := validateInput(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "must be a file") {
		t.Fatalf("expected must-be-file error, got: %v", err)
	}
}

func TestValidateInput_ValidFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateInput(f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProfileControlDomain(t *testing.T) {
	tests := []struct {
		prof Profile
		want string
	}{
		{ProfileAWSS3, "s3"}, {ProfileAWSIAM, "iam"}, {ProfileGCPGCS, "gcs"},
		{ProfileHIPAA, ""}, {ProfileCISv3, ""}, {ProfileSOC2, ""},
		{ProfilePCIDSSv4, ""}, {ProfileNIST, ""}, {ProfileFedRAMP, ""},
		{ProfileGDPR, ""}, {ProfileFFIEC, ""}, {ProfileISO27001, ""}, {ProfileNISTCSF, ""},
	}
	for _, tt := range tests {
		if got := profileControlDomain(tt.prof); got != tt.want {
			t.Fatalf("profileControlDomain(%q) = %q, want %q", tt.prof, got, tt.want)
		}
	}
}

func TestProfileComplianceFramework(t *testing.T) {
	tests := []struct {
		prof Profile
		want policy.ComplianceFramework
	}{
		{ProfileAWSS3, ""}, {ProfileHIPAA, "hipaa"}, {ProfileCISv3, "cis_aws_v3.0"},
		{ProfileSOC2, "soc2"}, {ProfilePCIDSSv4, "pci_dss_v4.0"}, {ProfileNIST, "nist_800_53_r5"},
		{ProfileFedRAMP, "fedramp_moderate"}, {ProfileGDPR, "gdpr"}, {ProfileFFIEC, "ffiec"},
		{ProfileISO27001, "iso_27001_2022"}, {ProfileNISTCSF, "nist_csf_2.0"},
	}
	for _, tt := range tests {
		if got := profileComplianceFramework(tt.prof); got != tt.want {
			t.Fatalf("profileComplianceFramework(%q) = %q, want %q", tt.prof, got, tt.want)
		}
	}
}

func TestFilterByCompliance(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.S3.PUBLIC.001", Compliance: policy.ComplianceMapping{"hipaa": "164.312(a)(1)"}},
		{ID: "CTL.S3.POLICY.WRITE.001", Compliance: nil},
		{ID: "CTL.RDS.ENCRYPT.001", Compliance: policy.ComplianceMapping{"hipaa": "164.312(a)(2)(iv)"}},
		{ID: "CTL.EC2.IMDSV2.001", Compliance: policy.ComplianceMapping{"cis_aws_v1.4.0": "5.6"}},
	}
	got := filterByCompliance(controls, "hipaa")
	if len(got) != 2 || got[0].ID != "CTL.S3.PUBLIC.001" || got[1].ID != "CTL.RDS.ENCRYPT.001" {
		t.Fatalf("filterByCompliance: unexpected result: %v", got)
	}
}

func TestFilterByComplianceUnion(t *testing.T) {
	hipaa := policy.ComplianceMapping{"hipaa": ""}
	soc2 := policy.ComplianceMapping{"soc2": ""}
	both := policy.ComplianceMapping{"hipaa": "", "soc2": ""}

	cases := []struct {
		name       string
		controls   []policy.ControlDefinition
		frameworks []policy.ComplianceFramework
		want       int
	}{
		{"single", []policy.ControlDefinition{{ID: "A", Compliance: hipaa}, {ID: "B", Compliance: soc2}, {ID: "C", Compliance: hipaa}}, []policy.ComplianceFramework{"hipaa"}, 2},
		{"multi", []policy.ControlDefinition{{ID: "A", Compliance: hipaa}, {ID: "B", Compliance: soc2}, {ID: "C", Compliance: policy.ComplianceMapping{"pci-dss": ""}}}, []policy.ComplianceFramework{"hipaa", "soc2"}, 2},
		{"dedup", []policy.ControlDefinition{{ID: "A", Compliance: both}, {ID: "B", Compliance: hipaa}}, []policy.ComplianceFramework{"hipaa", "soc2"}, 2},
		{"nomatch", []policy.ControlDefinition{{ID: "A", Compliance: hipaa}}, []policy.ComplianceFramework{"soc2"}, 0},
		{"empty", []policy.ControlDefinition{{ID: "A", Compliance: hipaa}}, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := filterByComplianceUnion(tc.controls, tc.frameworks); len(got) != tc.want {
				t.Fatalf("got %d controls, want %d", len(got), tc.want)
			}
		})
	}
}

func TestResolveScopeFilter(t *testing.T) {
	if resolveScopeFilter(ProfileAWSS3, true, nil) == nil {
		t.Error("IncludeAll: expected non-nil filter")
	}
	if resolveScopeFilter(ProfileAWSS3, false, []string{"bucket-a"}) == nil {
		t.Error("Allowlist: expected non-nil filter")
	}
	if resolveScopeFilter(ProfileAWSS3, false, nil) == nil {
		t.Error("Default: expected non-nil filter")
	}
}

func TestFilterSnapshots_Empty(t *testing.T) {
	filtered, warnings := filterSnapshots(ProfileAWSS3, ProfileRequest{IncludeAll: true}, nil)
	if filtered != nil {
		t.Fatal("expected nil filtered for empty snapshots")
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "No snapshots") {
		t.Fatalf("expected 'No snapshots' warning, got: %v", warnings)
	}
}

func TestFinalizeProfileEvaluation_NoFindings(t *testing.T) {
	result := evaluation.ComplianceReport{Findings: nil}
	out := finalizeProfileEvaluation(&result, nil, "ctl", "input")
	if out.HasViolations {
		t.Fatal("expected no violations")
	}
	joined := strings.Join(out.Warnings, "\n")
	if !strings.Contains(joined, "No violations found") {
		t.Fatalf("expected success message, got: %v", out.Warnings)
	}
}

func TestFinalizeProfileEvaluation_WithFindings(t *testing.T) {
	result := evaluation.ComplianceReport{Findings: []evaluation.Finding{{ControlID: "CTL.TEST.001"}}}
	out := finalizeProfileEvaluation(&result, nil, "ctl", "input")
	if !out.HasViolations {
		t.Fatal("expected HasViolations")
	}
	if out.DiagnoseHint == "" {
		t.Fatal("expected a diagnose hint")
	}
}

func TestLatestSnapshotSource(t *testing.T) {
	base := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	latest := []asset.Snapshot{
		{Source: asset.SourceLocal, CapturedAt: base},
		{Source: asset.SourcePlanned, CapturedAt: base.Add(time.Hour)},
	}
	if got := latestSnapshotSource(latest); got != asset.SourcePlanned {
		t.Fatalf("latest populated source must win: got %q, want %q", got, asset.SourcePlanned)
	}

	single := []asset.Snapshot{{Source: asset.SourcePlanned, CapturedAt: base}}
	if got := latestSnapshotSource(single); got != asset.SourcePlanned {
		t.Fatalf("got %q, want %q", got, asset.SourcePlanned)
	}

	blank := []asset.Snapshot{{CapturedAt: base}, {CapturedAt: base.Add(time.Hour)}}
	if got := latestSnapshotSource(blank); got != asset.SourceDeployed {
		t.Fatalf("default: got %q, want %q", got, asset.SourceDeployed)
	}
}

// TestEmptyScope_EmitsDocument asserts a --format json profile run whose
// allowlist scopes out every asset still emits one parseable JSON document
// (the "one document per invocation" contract).
func TestEmptyScope_EmitsDocument(t *testing.T) {
	inputFile := filepath.Join(repoRoot(t), "testdata", "e2e", "aws-s3-obs-public", "observations.json")
	res, err := EvaluateProfile(context.Background(), ProfileRequest{
		InputFile:       inputFile,
		Profiles:        []string{string(ProfileAWSS3)},
		BucketAllowlist: []string{"arn:aws:s3:::typo-bucket-that-matches-nothing"},
		Format:          "json",
	})
	if err != nil {
		t.Fatalf("EvaluateProfile: %v", err)
	}
	out := res.Output
	if len(bytes.TrimSpace(out)) == 0 {
		t.Fatal("empty-scope --format json run produced NO output document")
	}
	var doc any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\n%s", err, out)
	}
}
