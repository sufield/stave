package predindex

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestBuild_PathMaxSeverity_InfoSeverityRecorded(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       kernel.ControlID("CTL.S3.INFO.001"),
			Severity: policy.SeverityInfo,
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{
						Field: predicate.NewFieldPath("properties.storage.info_flag"),
						Op:    predicate.OpEq,
						Value: policy.NewOperand(true),
					},
				},
			},
		},
	}

	idx := Build(controls, nil)
	got, ok := idx.PathMaxSeverity["properties.storage.info_flag"]
	if !ok {
		t.Fatalf("expected PathMaxSeverity to contain path 'properties.storage.info_flag'")
	}
	if got != policy.SeverityInfo {
		t.Errorf("expected PathMaxSeverity = %v (%s), got %v (%s)", policy.SeverityInfo, policy.SeverityInfo, got, got)
	}
}
