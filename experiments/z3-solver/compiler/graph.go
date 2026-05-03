package compiler

import (
	"github.com/sufield/stave/pkg/stave"
)

// compileGraph layers the asset-relationship view from the
// PolicyExport / GraphExport on top of the policy compilation.
// The compiled trust edges drive multi-hop reachability in the
// reachability query; encryption edges feed the kms:Decrypt
// requirement the IAM evaluator overlays at query time.
//
// The graph itself is consumed mostly by query-side code (see
// queries/reachability.go). compileGraph populates the model
// fields downstream queries read; it does not push assertions
// onto a global solver — keeping the model query-neutral.
func (m *CompiledModel) compileGraph(g *stave.GraphExport, p *stave.PolicyExport) error {
	if p != nil {
		for _, e := range p.AssetRelationships {
			switch e.Relationship {
			case "encrypts_with":
				m.EncryptionEdges = append(m.EncryptionEdges, EncryptionEdge{
					Resource: e.FromAssetID,
					KMSKey:   e.ToAssetID,
				})
			case "assumes":
				m.TrustEdges = append(m.TrustEdges, TrustEdge{
					Assumer: e.FromAssetID,
					Assumee: e.ToAssetID,
				})
			}
		}
	}
	// GraphExport adds per-finding edges (finding_about,
	// chain_member); those are useful for shadow-mode comparisons
	// but not for the IAM evaluator. We keep them on g and the
	// shadow comparator reads them directly.
	_ = g
	return nil
}

// CanAssumeBounded reports whether the symbolic principal can
// reach the target role through up to maxHops trust edges. The
// expansion is closed-form (a disjunction over precomputed
// transitive closures) so the query stays decidable for any
// finite snapshot.
//
// The function is exported because the reachability query owns
// the per-query symbolic principal and target — it threads them
// through this builder rather than letting the compiler bake
// query-specific constants into shared state.
func (m *CompiledModel) CanAssumeBounded(from, to string, maxHops int) bool {
	if maxHops <= 0 {
		return false
	}
	// Direct edge.
	for _, e := range m.TrustEdges {
		if e.Assumer == from && e.Assumee == to {
			return true
		}
	}
	if maxHops == 1 {
		return false
	}
	// Multi-hop: depth-first walk over TrustEdges. Cycles are
	// guarded by the visited set so a self-trust loop does not
	// cause a stack blow-up.
	visited := map[string]bool{from: true}
	var dfs func(current string, depth int) bool
	dfs = func(current string, depth int) bool {
		if depth == 0 {
			return false
		}
		for _, e := range m.TrustEdges {
			if e.Assumer != current {
				continue
			}
			if e.Assumee == to {
				return true
			}
			if visited[e.Assumee] {
				continue
			}
			visited[e.Assumee] = true
			if dfs(e.Assumee, depth-1) {
				return true
			}
		}
		return false
	}
	return dfs(from, maxHops)
}
