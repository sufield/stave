package compare

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestBugHunt_AnalyzeParity_MixedItemsSorted(t *testing.T) {
	// Environments: prod, staging, dev
	// Let's create two mixed controls:
	// - CTL.B: fails in prod and dev, passes in staging.
	// - CTL.A: fails in prod and staging, passes in dev.
	// Both should be in Mixed items.
	envs := map[string][]remediation.Finding{
		"prod": {
			{Finding: evaluation.Finding{ControlID: "CTL.B", ControlSeverity: policy.SeverityHigh}},
			{Finding: evaluation.Finding{ControlID: "CTL.A", ControlSeverity: policy.SeverityHigh}},
		},
		"staging": {
			{Finding: evaluation.Finding{ControlID: "CTL.A", ControlSeverity: policy.SeverityHigh}},
		},
		"dev": {
			{Finding: evaluation.Finding{ControlID: "CTL.B", ControlSeverity: policy.SeverityHigh}},
		},
	}

	result := AnalyzeParity(ParityInput{
		Environments: envs,
		EnvOrder:     []string{"prod", "staging", "dev"},
	})

	if len(result.MixedItems) != 2 {
		t.Fatalf("expected 2 mixed items, got %d", len(result.MixedItems))
	}

	// We expect MixedItems to be sorted by severity (both High) then alphabetically by ControlID:
	// CTL.A then CTL.B.
	// Under the buggy code: mixed is never sorted, so order depends on Go map iteration.
	if result.MixedItems[0].ControlID != "CTL.A" {
		t.Errorf("expected first mixed item to be CTL.A, got %s", result.MixedItems[0].ControlID)
	}
	if result.MixedItems[1].ControlID != "CTL.B" {
		t.Errorf("expected second mixed item to be CTL.B, got %s", result.MixedItems[1].ControlID)
	}
}
