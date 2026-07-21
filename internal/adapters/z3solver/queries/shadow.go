//go:build cgo && z3

package queries

import (
	"fmt"
	"time"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/internal/adapters/z3solver/compiler"
)

// ShadowedDeny records a Deny statement that is bypassed by a broader Allow.
type ShadowedDeny struct {
	DenyIndex   int               `json:"deny_index"`
	DenySid     string            `json:"deny_sid"`
	DenyAssetID string            `json:"deny_asset_id"`
	Witness     map[string]string `json:"witness,omitempty"`
}

// QueryShadow checks whether any Deny statement is bypassed by a
// broader Allow. For each Deny, it asserts Allow(request) ∧ ¬Deny(request).
// SAT means the Deny is shadowed — the witness shows the gap.
func QueryShadow(model *compiler.CompiledModel) *QueryResult {
	start := time.Now()

	r := &QueryResult{
		QueryName: "shadow",
		ModelCoverage: ModelCoverage{
			Modeled:    []string{"identity_policy", "resource_policy", "kms_key_policy"},
			NotModeled: []string{"scp", "permissions_boundary", "session_policy"},
		},
	}

	var allows []z3.Bool
	var denyStmts []int
	for i := range model.Stmt {
		s := &model.Stmt[i]
		match := s.PrincipalMatch.And(s.ActionMatch, s.ResourceMatch, s.ConditionMatch)
		switch s.Effect {
		case "Allow":
			allows = append(allows, match)
		case "Deny":
			denyStmts = append(denyStmts, i)
		}
	}
	if len(allows) == 0 || len(denyStmts) == 0 {
		r.Result = "unsatisfiable"
		r.Interpretation = "no shadow possible: the model has no Allow/Deny pair"
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	allowExpr := orOf(model.Ctx, allows)

	var shadows []ShadowedDeny
	for _, di := range denyStmts {
		ds := &model.Stmt[di]
		denyMatch := ds.PrincipalMatch.And(ds.ActionMatch, ds.ResourceMatch, ds.ConditionMatch)

		solver := z3.NewSolver(model.Ctx)
		solver.Assert(allowExpr)
		solver.Assert(denyMatch.Not())

		sat, err := solver.Check()
		if err != nil {
			continue
		}
		if sat {
			sd := ShadowedDeny{
				DenyIndex:   di,
				DenySid:     ds.Sid,
				DenyAssetID: ds.SourceAssetID,
			}
			if w := extractTriple(solver, model); w != nil {
				sd.Witness = w
			}
			shadows = append(shadows, sd)
		}
	}

	r.SolveTimeMs = time.Since(start).Milliseconds()
	if len(shadows) > 0 {
		r.Result = "satisfiable"
		r.Interpretation = fmt.Sprintf("%d Deny statement(s) shadowed: an Allow matches requests the Deny does not cover", len(shadows))
		r.Witness = shadows[0].Witness
	} else {
		r.Result = "unsatisfiable"
		r.Interpretation = "no Deny is shadowed: every Deny fully covers its scope against all Allows"
	}
	return r
}
