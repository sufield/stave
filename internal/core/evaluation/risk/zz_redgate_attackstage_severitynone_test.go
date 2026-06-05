package risk

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Test_RedGate_AttackStageSeverityNone asserts the CORRECT behavior:
// a stage that has an ACTIVE failing control must not be labeled "PASS"
// (which is the label reserved for stages with NO failing controls at
// all). The control here has Severity SeverityNone, which the
// worst-severity tracking (`if sev > worstPerStage[stage]`) refuses to
// store because SeverityNone == 0 and 0 > 0 is false, so emission marks
// the stage "PASS" — indistinguishable from a clean stage.
func Test_RedGate_AttackStageSeverityNone(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BuildAttackStageSummary panicked: %v", r)
		}
	}()

	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"c1": {
			Severity: policy.SeverityNone,
			Params:   policy.NewParams(map[string]any{"attack_stage": "impact"}),
		},
	}
	failures := []FailingControl{
		{ControlID: "c1", AssetID: asset.ID("a1")},
	}

	summary := BuildAttackStageSummary(failures, lookup)

	// "impact" has an active failure (c1), so it must not be reported as
	// a clean/passing stage.
	if summary["impact"] == "PASS" {
		t.Fatalf("impact stage has an active failing control but was labeled %q; an active failure must not be reported as PASS", summary["impact"])
	}
}
