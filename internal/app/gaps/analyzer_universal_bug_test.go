package gaps

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestAnalyze_UniversalControlsWithEmptyApplicableAssetTypesIncluded(t *testing.T) {
	// Specific control declaring aws_s3_bucket
	c2 := ctl("CTL.S3.001", policy.SeverityHigh, []kernel.AssetType{"aws_s3_bucket"}, "properties.logging.enabled")

	// Universal control with nil/empty ApplicableAssetTypes (applies to ALL asset types)
	universalControl := ctl("CTL.UNIVERSAL.001", policy.SeverityHigh, nil, "properties.logging.enabled")

	a1 := obs("b1", "aws_s3_bucket", map[string]any{}) // missing properties.logging.enabled

	rep := Analyze([]policy.ControlDefinition{c2, universalControl}, nil, []asset.Snapshot{snap(time.Now(), a1)}, 0)
	if len(rep.Gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(rep.Gaps))
	}

	// BOTH CTL.S3.001 and CTL.UNIVERSAL.001 must be listed in ControlsBlocked
	if len(rep.Gaps[0].ControlsBlocked) != 2 {
		t.Fatalf("expected 2 controls blocked (including universal control), got %d: %v", len(rep.Gaps[0].ControlsBlocked), rep.Gaps[0].ControlsBlocked)
	}
}
