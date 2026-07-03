package ocsf

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_OCSF_ResourceTypeMapping(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID:       "CTL.S3.PUBLIC.001",
				AssetID:         asset.ID("arn:aws:s3:::prod-bucket"),
				AssetType:       kernel.AssetType("aws_s3_bucket"),
				ControlSeverity: policy.SeverityHigh,
			},
		},
	}

	events := Export(findings)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if len(e.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(e.Resources))
	}

	r := e.Resources[0]
	if r.UID != "arn:aws:s3:::prod-bucket" {
		t.Errorf("expected resource UID to be 'arn:aws:s3:::prod-bucket', got %q", r.UID)
	}

	// Under the buggy code: r.Type = "arn:aws:s3:::prod-bucket"
	// Under the correct code: r.Type = "aws_s3_bucket"
	if r.Type != "aws_s3_bucket" {
		t.Errorf("expected resource Type to be 'aws_s3_bucket', got %q (likely mapped AssetID to both UID and Type)", r.Type)
	}
}
