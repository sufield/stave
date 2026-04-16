package ocsf

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestExport_ComplianceFindingSchema(t *testing.T) {
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{
			ControlID:       "CTL.S3.PUBLIC.001",
			ControlName:     "No Public S3 Buckets",
			AssetID:         asset.ID("arn:aws:s3:::prod-bucket"),
			ControlSeverity: policy.SeverityHigh,
		}},
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
			{Finding: evaluation.Finding{
				ControlID:       "CTL.TEST.001",
				AssetID:         asset.ID("test"),
				ControlSeverity: tt.severity,
			}},
		}
		events := Export(findings)
		if events[0].SeverityID != tt.wantID {
			t.Errorf("severity %v: got ID %d, want %d",
				tt.severity, events[0].SeverityID, tt.wantID)
		}
	}
}
