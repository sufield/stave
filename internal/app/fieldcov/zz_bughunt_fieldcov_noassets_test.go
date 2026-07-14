package fieldcov

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestBugHunt_Classify_NoAssets(t *testing.T) {
	// Control requires "aws_s3_bucket"
	ctl := policy.ControlDefinition{
		ID:                   "CTL.TEST.NOASSETS.001",
		Severity:             policy.SeverityHigh,
		ApplicableAssetTypes: []kernel.AssetType{"aws_s3_bucket"},
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq},
			},
		},
	}

	// Snapshot only has "aws_iam_role", no "aws_s3_bucket"
	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Type: "aws_iam_role",
					Properties: map[string]any{
						"storage": map[string]any{
							"kind": "bucket",
						},
					},
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  []policy.ControlDefinition{ctl},
		Snapshots: snapshots,
	})

	if report.Summary.NoAssets != 1 {
		t.Errorf("expected Summary.NoAssets = 1, got %d", report.Summary.NoAssets)
	}

	if len(report.IncompleteResults) > 0 || len(report.SilentRisk) > 0 {
		t.Errorf("expected NoAssets results to not be classified as incomplete or silent risk")
	}
}
