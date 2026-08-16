package findingfilter

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
	tNow := t0.Add(10 * 24 * time.Hour)

	// findingBucket was present in history (chronic)
	findingBucket := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			AssetID:         asset.ID("shared-id"),
			AssetType:       kernel.AssetType("aws_s3_bucket"),
			ControlSeverity: policy.SeverityHigh,
		},
	}

	// findingRole is BRAND NEW (never seen in history), but has the same AssetID "shared-id"
	findingRole := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			AssetID:         asset.ID("shared-id"),
			AssetType:       kernel.AssetType("aws_iam_role"),
			ControlSeverity: policy.SeverityHigh,
		},
	}

	history := []*report.Assessment{
		{
			Run:      evaluation.RunInfo{EvalTime: t0},
			Findings: []remediation.Finding{findingBucket},
		},
	}

	in := Input{
		CurrentFindings: []remediation.Finding{findingBucket, findingRole},
		History:         history,
		EvalTime:        tNow,
	}

	res := Classify(in)

	// findingRole MUST be classified as NEW (len(NewFindings) == 1)
	// without AssetType in findingKey, findingRole collides with findingBucket and gets falsely suppressed as CHRONIC
	if len(res.NewFindings) != 1 {
		t.Fatalf("expected 1 NEW finding (aws_iam_role), got %d new findings", len(res.NewFindings))
	}

	if res.NewFindings[0].Finding.AssetType != kernel.AssetType("aws_iam_role") {
		t.Errorf("expected new finding to be aws_iam_role, got %v", res.NewFindings[0].Finding.AssetType)
	}
}
