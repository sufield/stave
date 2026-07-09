//go:build cgo && z3

package compiler

func (m *CompiledModel) compileGraph(g *GraphExport, p *PolicyExport) error {
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
	_ = g
	return nil
}

// CanAssumeBounded reports whether the principal can reach the target
// role through up to maxHops trust edges.
func (m *CompiledModel) CanAssumeBounded(from, to string, maxHops int) bool {
	if maxHops <= 0 {
		return false
	}
	for _, e := range m.TrustEdges {
		if e.Assumer == from && e.Assumee == to {
			return true
		}
	}
	if maxHops == 1 {
		return false
	}
	visited := map[string]struct{}{from: {}}
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
			if _, ok := visited[e.Assumee]; ok {
				continue
			}
			visited[e.Assumee] = struct{}{}
			if dfs(e.Assumee, depth-1) {
				return true
			}
		}
		return false
	}
	return dfs(from, maxHops)
}
