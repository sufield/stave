package fieldcov

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestAnalyze_NestedArrayElementPropertiesRecognized(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			{
				Type: kernel.AssetType("aws_s3_bucket"),
				Properties: map[string]any{
					"storage": map[string]any{
						"rules": []any{
							map[string]any{
								"status": "Enabled",
							},
						},
					},
				},
			},
		},
	}

	ctl := policy.ControlDefinition{
		ID:                   kernel.ControlID("CTL.S3.001"),
		ApplicableAssetTypes: []kernel.AssetType{"aws_s3_bucket"},
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{
					Field: predicate.NewFieldPath("properties.storage.rules.status"),
					Op:    predicate.OpEq,
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  []policy.ControlDefinition{ctl},
		Snapshots: []asset.Snapshot{snap},
	})

	if len(report.IncompleteResults) != 0 {
		t.Fatalf("expected 0 incomplete results for present array property, got %d", len(report.IncompleteResults))
	}

	if report.Summary.Evaluable != 1 {
		t.Errorf("expected 1 evaluable control, got %d", report.Summary.Evaluable)
	}
}
