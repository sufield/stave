package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestMarshalRemediationFieldPresent pins the regression: when
// evaluation.Finding has a custom MarshalJSON, Go's JSON encoder
// promotes that method to the embedding remediation.Finding,
// silently dropping the outer struct's RemediationSpec and
// RemediationPlan fields. The fix is the explicit MarshalJSON on
// remediation.Finding that splices the embedded JSON with the
// outer fields.
func TestMarshalRemediationFieldPresent(t *testing.T) {
	t.Parallel()
	rf := Finding{
		Finding:         evaluation.Finding{ControlID: "X", AssetID: "Y"},
		RemediationSpec: policy.RemediationSpec{Description: "do thing", Action: "run cmd"},
	}
	out, err := json.Marshal(&rf)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"remediation"`, `"do thing"`, `"run cmd"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in JSON: %s", want, out)
		}
	}
}

// TestRemediationFindingRoundtrip pins symmetric encoding: a
// finding with SLA state and a remediation spec marshalled and
// unmarshalled must reproduce both layers.
func TestRemediationFindingRoundtrip(t *testing.T) {
	t.Parallel()
	deadline := 24.0
	original := Finding{
		Finding:         evaluation.Finding{ControlID: "C.1", AssetID: "A.1"},
		RemediationSpec: policy.RemediationSpec{Description: "d", Action: "a"},
	}
	original.RehydrateSLA(&deadline, true, nil, policy.SeverityHigh,
		kernel.SLAPolicySourceControlOverride)

	raw, err := json.Marshal(&original)
	if err != nil {
		t.Fatal(err)
	}
	var got Finding
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.RemediationSpec.Action != "a" || got.RemediationSpec.Description != "d" {
		t.Errorf("remediation roundtrip lost: %+v", got.RemediationSpec)
	}
	if !got.IsAnyBreach() {
		t.Error("SLA breach state lost in round-trip")
	}
	if dl, ok := got.SLADeadlineValue(); !ok || dl != deadline {
		t.Errorf("deadline = (%v, %v), want (%v, true)", dl, ok, deadline)
	}
}
