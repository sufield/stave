package exemptionsuggest

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

func TestSuggest_DistinctAssetTypesWithSameIDDoNotCollide(t *testing.T) {
	t0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	tNow := t0.Add(40 * 24 * time.Hour)

	// findingBucket open since t0 (40 days ago)
	findingBucket := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			AssetID:         asset.ID("shared-id"),
			AssetType:       kernel.AssetType("aws_s3_bucket"),
			ControlSeverity: policy.SeverityHigh,
		},
	}

	// findingRole also open since t0 (40 days ago) with SAME asset ID "shared-id"
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
			Findings: []remediation.Finding{findingBucket, findingRole},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: tNow},
			Findings: []remediation.Finding{findingBucket, findingRole},
		},
	}

	in := Input{
		History:      history,
		Window:       60 * 24 * time.Hour,
		MinDwell:     14 * 24 * time.Hour,
		EvalTime:     tNow,
		ExemptedKeys: map[string]struct{}{},
	}

	res := Suggest(in)

	if len(res.Chronic) != 2 {
		t.Fatalf("expected 2 chronic candidates for distinct asset types with shared asset ID, got %d", len(res.Chronic))
	}
}
