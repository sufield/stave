package gaps

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestBugHunt_Prioritize_AssetTypeTieBreaker(t *testing.T) {
	// Two gaps with identical properties (same path, same severity, etc.) but different asset types.
	// Since prioritize does not compare AssetType as a final tie-breaker, their relative order is unstable.
	gapsList := []FieldGap{
		{
			PropertyPath: "properties.tags.environment",
			AssetType:    "rds_instance",
			MaxSeverity:  policy.SeverityHigh,
		},
		{
			PropertyPath: "properties.tags.environment",
			AssetType:    "ec2_instance",
			MaxSeverity:  policy.SeverityHigh,
		},
	}

	Prioritize(gapsList)

	// We expect the gaps to be sorted alphabetically by AssetType: "ec2_instance" then "rds_instance"
	if gapsList[0].AssetType != "ec2_instance" {
		t.Errorf("gapsList[0].AssetType = %q, want ec2_instance", gapsList[0].AssetType)
	}
	if gapsList[1].AssetType != "rds_instance" {
		t.Errorf("gapsList[1].AssetType = %q, want rds_instance", gapsList[1].AssetType)
	}
}
