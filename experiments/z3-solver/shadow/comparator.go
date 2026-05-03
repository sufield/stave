// Package shadow runs Stave's CEL evaluation alongside the Z3
// experiment and emits an agreement/disagreement report. The
// comparator is the experiment's accountability layer: it answers
// "where does the formal model say something the empirical
// evaluator missed, and vice versa?".
package shadow

import (
	"github.com/sufield/stave/experiments/z3-solver/compiler"
	"github.com/sufield/stave/experiments/z3-solver/loader"
	"github.com/sufield/stave/experiments/z3-solver/queries"
)

// ComparisonResult is the wire shape of a shadow run.
type ComparisonResult struct {
	FixtureDir       string       `json:"fixture_dir"`
	CELFindings      int          `json:"cel_findings"`
	Z3InvariantFails int          `json:"z3_invariant_fails"`
	Agreements       int          `json:"agreements"`
	Z3Only           []ShadowItem `json:"z3_only,omitempty"`
	CELOnly          []ShadowItem `json:"cel_only,omitempty"`
	AgreementRate    float64      `json:"agreement_rate"`
	NotModeled       []string     `json:"not_modeled,omitempty"`
}

// ShadowItem names one disagreement: a control ID where one
// evaluator reported a finding and the other did not.
type ShadowItem struct {
	ControlID      string `json:"control_id"`
	Reason         string `json:"reason"`
	Interpretation string `json:"interpretation"`
}

// Compare runs every loaded invariant through QueryInvariantVerify
// and matches the results against the assessment's CEL-derived
// findings. The match is by control ID:
//
//   - AGREE_FAIL: both Z3 and CEL flag the control.
//   - AGREE_PASS: neither flags it.
//   - Z3_ONLY:    Z3 says the unsafe predicate is satisfiable
//     (vulnerability exists in the modeled fragment) but CEL
//     produced no finding for the snapshot's concrete values.
//   - CEL_ONLY:   CEL flagged the control on a concrete asset but
//     the Z3 invariant verification answered UNSAT — the control
//     fired against this snapshot's values but the modeled
//     predicate is otherwise unreachable. Often this means the
//     Z3 model is too conservative (NotModeled gaps).
func Compare(model *compiler.CompiledModel, exports *loader.StaveExports, fixtureDir string) *ComparisonResult {
	result := &ComparisonResult{FixtureDir: fixtureDir}

	celByControl := map[string]int{}
	for _, f := range exports.Assessment.Findings {
		celByControl[string(f.ControlID)]++
	}
	result.CELFindings = len(exports.Assessment.Findings)

	z3FailByControl := map[string]*queries.QueryResult{}
	for id := range model.Invariants {
		r := queries.QueryInvariantVerify(model, string(id))
		if r.Result == "satisfiable" {
			z3FailByControl[string(id)] = r
			result.Z3InvariantFails++
		}
	}

	for cid := range celByControl {
		if _, ok := z3FailByControl[cid]; ok {
			result.Agreements++
			continue
		}
		result.CELOnly = append(result.CELOnly, ShadowItem{
			ControlID:      cid,
			Reason:         "cel_fired_z3_unsat",
			Interpretation: "CEL flagged this control against snapshot values but the modeled predicate is UNSAT — likely a model coverage gap",
		})
	}
	for cid, r := range z3FailByControl {
		if _, ok := celByControl[cid]; ok {
			continue
		}
		result.Z3Only = append(result.Z3Only, ShadowItem{
			ControlID:      cid,
			Reason:         "z3_sat_cel_silent",
			Interpretation: r.Interpretation,
		})
	}

	total := result.Agreements + len(result.Z3Only) + len(result.CELOnly)
	if total > 0 {
		result.AgreementRate = float64(result.Agreements) / float64(total)
	}
	return result
}
