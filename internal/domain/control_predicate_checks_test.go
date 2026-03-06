package domain

import (
	"testing"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/diag"

	"github.com/sufield/stave/internal/domain/policy"
)

func TestFindMissingParamReferences_DedupesAndSorts(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{ValueFromParam: "z"},
			{
				All: []policy.PredicateRule{
					{ValueFromParam: "b"},
					{ValueFromParam: "z"},
				},
			},
		},
		All: []policy.PredicateRule{
			{ValueFromParam: "a"},
			{ValueFromParam: "b"},
		},
	}

	got := policy.FindMissingParamReferences(pred, policy.ControlParams{
		"a": "present",
	})

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
					{Field: "properties.public", Op: "eq", Value: true},
				},
			},
		},
		{
			ID:   "CTL.NEVER",
			Name: "Never",
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: "properties.nonexistent", Op: "eq", Value: true},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Resources: []asset.Asset{
				{
					ID: "r1",
					Properties: map[string]any{
						"public": true,
					},
				},
			},
		},
	}

	issues := policy.CheckControlEffectiveness(controls, snapshots)
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
