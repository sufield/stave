//go:build cgo && z3

package stave

import (
	"context"
	"fmt"
	"os"

	"github.com/sufield/stave/internal/adapters/z3solver/compiler"
	"github.com/sufield/stave/internal/adapters/z3solver/queries"
)

// ProveConfig configures a prove query.
type ProveConfig struct {
	SnapshotsDir    string
	ControlsDir     string
	Query           string
	Principal       string
	Action          string
	Resource        string
	InvariantID     string
	CertificatePath string
}

// ProveResult wraps the Z3 query result for the facade.
type ProveResult = queries.QueryResult

// Prove loads a Stave assessment, compiles it into a Z3 model, and
// runs the requested query.
func Prove(ctx context.Context, cfg ProveConfig) (*ProveResult, error) {
	if cfg.SnapshotsDir == "" {
		return nil, fmt.Errorf("prove: --observations is required")
	}
	if cfg.Query == "" {
		return nil, fmt.Errorf("prove: --query is required")
	}

	exports, err := loadProveExports(ctx, cfg)
	if err != nil {
		return nil, err
	}

	model, err := compiler.Compile(exports)
	if err != nil {
		return nil, fmt.Errorf("prove: compile Z3 model: %w", err)
	}

	var result *ProveResult
	switch cfg.Query {
	case "compatibility":
		result = queries.QueryCompatibility(model, cfg.Principal, cfg.Action, cfg.Resource)
	case "reachability":
		result = queries.QueryReachability(model, cfg.Principal, cfg.Resource)
	case "conflict":
		result = queries.QueryConflict(model)
	case "choke-point":
		reach := queries.QueryReachability(model, cfg.Principal, cfg.Resource)
		result = queries.QueryChokePoint(model, reach)
	case "invariant":
		result = queries.QueryInvariantVerify(model, cfg.InvariantID)
	default:
		return nil, fmt.Errorf("prove: unknown query %q (valid: compatibility, reachability, conflict, choke-point, invariant)", cfg.Query)
	}

	if cfg.CertificatePath != "" && result.CertificateSMT != "" {
		if err := os.WriteFile(cfg.CertificatePath, []byte(result.CertificateSMT), 0o644); err != nil {
			return nil, fmt.Errorf("prove: write certificate: %w", err)
		}
	}

	return result, nil
}

func loadProveExports(ctx context.Context, cfg ProveConfig) (*compiler.Exports, error) {
	assessment, err := Apply(ctx, Config{
		SnapshotsDir: cfg.SnapshotsDir,
		ControlsDir:  cfg.ControlsDir,
	})
	if err != nil {
		return nil, fmt.Errorf("prove: stave.Apply: %w", err)
	}

	policies, err := ExportPolicies(ctx, ExportConfig{
		SnapshotsDir: cfg.SnapshotsDir,
	})
	if err != nil {
		return nil, fmt.Errorf("prove: stave.ExportPolicies: %w", err)
	}

	graph := ExportGraph(assessment)

	invariants, err := ExportInvariants(ctx, InvariantExportConfig{
		ControlsDir: cfg.ControlsDir,
	})
	if err != nil {
		return nil, fmt.Errorf("prove: stave.ExportInvariants: %w", err)
	}

	return toCompilerExports(policies, graph, invariants), nil
}

func toCompilerExports(p *PolicyExport, g *GraphExport, inv *InvariantExport) *compiler.Exports {
	return &compiler.Exports{
		Policies:   toCompilerPolicies(p),
		Graph:      toCompilerGraph(g),
		Invariants: toCompilerInvariants(inv),
	}
}

func toCompilerPolicies(p *PolicyExport) *compiler.PolicyExport {
	if p == nil {
		return nil
	}
	return &compiler.PolicyExport{
		ResourcePolicies:   toCompilerDocs(p.ResourcePolicies),
		TrustPolicies:      toCompilerTrustDocs(p.TrustPolicies),
		KMSKeyPolicies:     toCompilerDocs(p.KMSKeyPolicies),
		AssetRelationships: toCompilerEdges(p.AssetRelationships),
	}
}

func toCompilerDocs(docs []PolicyDocument) []compiler.PolicyDocument {
	out := make([]compiler.PolicyDocument, len(docs))
	for i, d := range docs {
		out[i] = compiler.PolicyDocument{
			SourceAssetID: d.SourceAssetID,
			PolicyType:    d.PolicyType,
			Statements:    toCompilerStmts(d.Statements),
		}
	}
	return out
}

func toCompilerTrustDocs(docs []TrustDocument) []compiler.TrustDocument {
	out := make([]compiler.TrustDocument, len(docs))
	for i, d := range docs {
		out[i] = compiler.TrustDocument{
			SourceAssetID: d.SourceAssetID,
			Statements:    toCompilerStmts(d.Statements),
		}
	}
	return out
}

func toCompilerStmts(stmts []PolicyStatement) []compiler.PolicyStatement {
	out := make([]compiler.PolicyStatement, len(stmts))
	for i, s := range stmts {
		out[i] = compiler.PolicyStatement{
			Sid:           s.Sid,
			Effect:        s.Effect,
			Principals:    s.Principals,
			NotPrincipals: s.NotPrincipals,
			Actions:       s.Actions,
			NotActions:    s.NotActions,
			Resources:     s.Resources,
			NotResources:  s.NotResources,
			Conditions:    toCompilerConditions(s.Conditions),
		}
	}
	return out
}

func toCompilerConditions(conds []Condition) []compiler.Condition {
	out := make([]compiler.Condition, len(conds))
	for i, c := range conds {
		out[i] = compiler.Condition(c)
	}
	return out
}

func toCompilerEdges(edges []AssetEdge) []compiler.AssetEdge {
	out := make([]compiler.AssetEdge, len(edges))
	for i, e := range edges {
		out[i] = compiler.AssetEdge(e)
	}
	return out
}

func toCompilerGraph(g *GraphExport) *compiler.GraphExport {
	if g == nil {
		return nil
	}
	nodes := make([]compiler.AssetNode, len(g.Assets))
	for i, a := range g.Assets {
		nodes[i] = compiler.AssetNode{
			ID:   string(a.ID),
			Type: string(a.Type),
		}
	}
	return &compiler.GraphExport{Assets: nodes}
}

func toCompilerInvariants(inv *InvariantExport) *compiler.InvariantExport {
	if inv == nil {
		return nil
	}
	defs := make([]compiler.InvariantDefinition, len(inv.Invariants))
	for i, d := range inv.Invariants {
		defs[i] = compiler.InvariantDefinition{
			ID:        string(d.ID),
			Severity:  string(d.Severity),
			Predicate: toCompilerPredicate(d.Predicate),
		}
	}
	return &compiler.InvariantExport{Invariants: defs}
}

func toCompilerPredicate(p PredicateExport) compiler.PredicateExport {
	if p.IsLeaf() {
		return compiler.PredicateExport{
			Property: p.Property,
			Operator: p.Operator,
			Expected: p.Expected,
		}
	}
	children := make([]compiler.PredicateExport, len(p.Children))
	for i, c := range p.Children {
		children[i] = toCompilerPredicate(c)
	}
	return compiler.PredicateExport{
		Combine:  p.Combine,
		Children: children,
	}
}
