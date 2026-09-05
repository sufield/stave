package oscillation

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func TestClassify_DistinctAssetTypesWithSameIDDoNotCollide(t *testing.T) {
	t0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)
	t2 := t0.Add(48 * time.Hour)

	// findingBucket fails only at t0
	findingBucket := remediation.Finding{
		ControlID:       kernel.ControlID("CTL.S3.001"),
		AssetID:         asset.ID("shared-id"),
		AssetType:       kernel.AssetType("aws_s3_bucket"),
		ControlSeverity: policy.SeverityHigh,
	}

	// findingRole fails at t1 and t2 on SAME asset ID "shared-id"
	findingRole := remediation.Finding{
		ControlID:       kernel.ControlID("CTL.S3.001"),
		AssetID:         asset.ID("shared-id"),
		AssetType:       kernel.AssetType("aws_iam_role"),
		ControlSeverity: policy.SeverityHigh,
	}

	assessments := []report.Assessment{
		{Run: evaluation.RunInfo{EvalTime: t0}, Findings: []remediation.Finding{findingBucket}},
		{Run: evaluation.RunInfo{EvalTime: t1}, Findings: []remediation.Finding{findingRole}},
		{Run: evaluation.RunInfo{EvalTime: t2}, Findings: []remediation.Finding{findingRole}},
	}

	// Target evaluation specifically for aws_s3_bucket
	in := Input{
		Assessments:     assessments,
		ControlID:       kernel.ControlID("CTL.S3.001"),
		AssetID:         asset.ID("shared-id"),
		AssetType:       kernel.AssetType("aws_s3_bucket"),
		MinOscillations: 2,
	}

	res := Classify(in)

	// For aws_s3_bucket, it failed in 1 of 3 assessments (failure rate = 1/3 = 0.33)
	// Without AssetType filtering, findingRole's failures at t1 and t2 blend in, giving 1.0 failure rate!
	if res.FailureRate > 0.5 {
		t.Fatalf("expected failure rate <= 0.5 for aws_s3_bucket, got %v (collided with aws_iam_role)", res.FailureRate)
	}
}
