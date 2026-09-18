package ocsf

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestExport_ComplianceFindingSchema(t *testing.T) {
	findings := []remediation.Finding{
		{
			ControlID:       "CTL.S3.PUBLIC.001",
			ControlName:     "No Public S3 Buckets",
			AssetID:         asset.ID("arn:aws:s3:::prod-bucket"),
			ControlSeverity: policy.SeverityHigh},
	}

	events := Export(findings)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}

	e := events[0]
	if e.ClassUID != 2003 {
		t.Errorf("class_uid = %d, want 2003", e.ClassUID)
	}
	if e.ClassName != "Compliance Finding" {
		t.Errorf("class_name = %q, want 'Compliance Finding'", e.ClassName)
	}
	if e.Finding.UID != "CTL.S3.PUBLIC.001:arn:aws:s3:::prod-bucket" {
		t.Errorf("finding.uid = %q", e.Finding.UID)
	}
	if e.Compliance.Control != "CTL.S3.PUBLIC.001" {
		t.Errorf("compliance.control = %q", e.Compliance.Control)
	}
	if e.Compliance.Status != "FAILED" {
		t.Errorf("compliance.status = %q, want FAILED", e.Compliance.Status)
	}
}

func TestExport_CCMv4Requirements(t *testing.T) {
	// Finding carrying two CCM v4 mappings surfaces them in the OCSF
	// compliance.requirements array, prefixed with "CCM:" so consumers
	// can filter by framework.
	findings := []remediation.Finding{
		{
			ControlID:       "CTL.IAM.ROOT.MFA.001",
			AssetID:         asset.ID("root"),
			ControlSeverity: policy.SeverityCritical,
			ControlCCMV4:    []string{"IAM-09", "IAM-14"}},
	}
	events := Export(findings)
	got := events[0].Compliance.Requirements
	want := []string{"CCM:IAM-09", "CCM:IAM-14"}
	if len(got) != len(want) {
		t.Fatalf("requirements = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("requirements[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExport_CCMv4Absent(t *testing.T) {
	// Finding without CCM mappings omits the requirements field.
	findings := []remediation.Finding{
		{
			ControlID:       "CTL.TEST.001",
			AssetID:         asset.ID("test"),
			ControlSeverity: policy.SeverityLow},
	}
	events := Export(findings)
	if events[0].Compliance.Requirements != nil {
		t.Errorf("requirements = %v, want nil", events[0].Compliance.Requirements)
	}
}

func TestExport_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity policy.Severity
		wantID   int
	}{
		{policy.SeverityCritical, 5},
		{policy.SeverityHigh, 4},
		{policy.SeverityMedium, 3},
		{policy.SeverityLow, 2},
	}
	for _, tt := range tests {
		findings := []remediation.Finding{
			{
				ControlID:       "CTL.TEST.001",
				AssetID:         asset.ID("test"),
				ControlSeverity: tt.severity},
		}
		events := Export(findings)
		if events[0].SeverityID != SeverityID(tt.wantID) {
			t.Errorf("severity %v: got ID %d, want %d",
				tt.severity, events[0].SeverityID, tt.wantID)
		}
	}
}

func TestComplianceFindings_DomainMethods(t *testing.T) {
	events := ComplianceFindings{
		{
			SeverityID: SeverityIDHigh,
			Compliance: OCSFCompliance{Control: "CTL.A.001"},
			Resources: OCSFResources{
				{UID: asset.ID("res-1"), Type: "aws_s3_bucket"},
			},
		},
		{
			SeverityID: SeverityIDLow,
			Compliance: OCSFCompliance{Control: "CTL.B.002"},
			Resources: OCSFResources{
				{UID: asset.ID("res-2"), Type: "aws_iam_user"},
			},
		},
	}

	if events.Len() != 2 {
		t.Errorf("events.Len() = %d, want 2", events.Len())
	}

	if events.BySeverity(SeverityIDHigh).Len() != 1 {
		t.Errorf("BySeverity(SeverityIDHigh) len = %d, want 1", events.BySeverity(SeverityIDHigh).Len())
	}

	if events.ByControl("CTL.A.001").Len() != 1 {
		t.Errorf("ByControl(CTL.A.001) len = %d, want 1", events.ByControl("CTL.A.001").Len())
	}

	var emptyEvents ComplianceFindings
	if emptyEvents.Len() != 0 || emptyEvents.BySeverity(SeverityIDHigh) != nil || emptyEvents.ByControl("CTL.A.001") != nil {
		t.Errorf("empty ComplianceFindings methods failed")
	}

	res := events[0].Resources
	if res.Len() != 1 {
		t.Errorf("res.Len() = %d, want 1", res.Len())
	}

	if res.ByType("aws_s3_bucket").Len() != 1 {
		t.Errorf("ByType(aws_s3_bucket) len = %d, want 1", res.ByType("aws_s3_bucket").Len())
	}

	if res.ByAssetID(asset.ID("res-1")) == nil {
		t.Errorf("ByAssetID(res-1) returned nil")
	}

	if res.ByAssetID(asset.ID("nonexistent")) != nil {
		t.Errorf("ByAssetID(nonexistent) expected nil")
	}

	var emptyRes OCSFResources
	if emptyRes.Len() != 0 || emptyRes.ByType("aws_s3_bucket") != nil || emptyRes.ByAssetID(asset.ID("res-1")) != nil {
		t.Errorf("empty OCSFResources methods failed")
	}
}
