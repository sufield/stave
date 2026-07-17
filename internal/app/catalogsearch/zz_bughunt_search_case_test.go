package catalogsearch

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Search_AttackStageCaseInsensitive(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       kernel.ControlID("CTL.S3.PUBLIC.001"),
			Name:     "No public S3 buckets",
			Severity: policy.SeverityCritical,
			Params:   policy.NewParams(map[string]any{"attack_stage": "credential_access"}),
		},
		{
			ID:       kernel.ControlID("CTL.EC2.IMDSV2.001"),
			Name:     "Require IMDSv2",
			Severity: policy.SeverityHigh,
			Params:   policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
		},
	}

	// We pass mixed case/uppercase filters for the attack stage.
	// Under buggy code, the comparison is case-sensitive, so the search returns 0 results.
	results := Search(controls, Filter{AttackStage: "Credential_Access"})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("control = %s, want CTL.S3.PUBLIC.001", results[0].ControlID)
	}
}
