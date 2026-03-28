package enginetest

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestFindMissingParamReferences_DedupesAndSorts(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{ValueFromParam: predicate.ParamRef("z")},
			{
				All: []policy.PredicateRule{
					{ValueFromParam: predicate.ParamRef("b")},
					{ValueFromParam: predicate.ParamRef("z")},
				},
			},
		},
		All: []policy.PredicateRule{
			{ValueFromParam: predicate.ParamRef("a")},
			{ValueFromParam: predicate.ParamRef("b")},
		},
	}

	got := pred.MissingParamReferences(policy.NewParams(map[string]any{
		"a": "present",
	}))

	if len(got) != 2 {
		t.Fatalf("missing refs len = %d, want 2 (%v)", len(got), got)
	}
	if got[0] != "b" || got[1] != "z" {
		t.Fatalf("missing refs = %v, want [b z]", got)
	}
}

func TestCheckControlEffectiveness(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.MATCH",
			Name: "Match",
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		{
			ID:   "CTL.NEVER",
			Name: "Never",
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.nonexistent"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					ID: "r1",
					Properties: map[string]any{
						"public": true,
					},
				},
			},
		},
	}

	issues := policy.CheckEffectiveness(controls, snapshots, testCELEvaluator())
	if len(issues) != 1 {
		t.Fatalf("issue count = %d, want 1 (%v)", len(issues), issues)
	}
	if issues[0].Code != diag.CodeControlNeverMatches {
		t.Fatalf("issue code = %q, want %q", issues[0].Code, diag.CodeControlNeverMatches)
	}
	if got, _ := issues[0].Evidence.Get("control_id"); got != "CTL.NEVER" {
		t.Fatalf("control_id evidence = %q, want CTL.NEVER", got)
	}
}
