package remediation

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

func TestBugHunt_ViolatedRequirements_Determinism(t *testing.T) {
	// A FindingSet with multiple findings violating different requirements.
	// Since ViolatedRequirements collects them in a map and iterates over it to build the result,
	// the output slice order is non-deterministic in the original code.
	set := FindingSet{
		{
			Finding: evaluation.Finding{
				ControlCompliance: policy.ComplianceMapping{
					"framework-a": "REQ-Z",
				},
			},
		},
		{
			Finding: evaluation.Finding{
				ControlCompliance: policy.ComplianceMapping{
					"framework-a": "REQ-A",
				},
			},
		},
	}

	violated := set.ViolatedRequirements("framework-a")
	if len(violated) != 2 {
		t.Fatalf("expected 2 violated requirements, got %d", len(violated))
	}

	// We expect the requirements to be sorted alphabetically: "REQ-A" then "REQ-Z"
	if violated[0] != "REQ-A" {
		t.Errorf("violated[0] = %q, want REQ-A", violated[0])
	}
	if violated[1] != "REQ-Z" {
		t.Errorf("violated[1] = %q, want REQ-Z", violated[1])
	}
}
