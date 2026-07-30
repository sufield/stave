//go:build cgo && z3

package compiler

import (
	"fmt"

	"github.com/aclements/go-z3/z3"
)

// CompiledModel holds the Z3 representation of a Stave assessment.
type CompiledModel struct {
	Ctx *z3.Context

	PrincipalSort z3.Sort
	ActionSort    z3.Sort
	ResourceSort  z3.Sort

	Principals map[string]z3.Uninterpreted
	Actions    map[string]z3.Uninterpreted
	Resources  map[string]z3.Uninterpreted

	Stmt            []CompiledStatement
	TrustEdges      []TrustEdge
	EncryptionEdges []EncryptionEdge
	Invariants      map[string]CompiledInvariant

	evalVarsCache *queryVars
}

// CompiledStatement is a Z3-ready view of one PolicyStatement.
type CompiledStatement struct {
	SourceAssetID string
	PolicyType    string
	Sid           string
	Effect        string

	PrincipalMatch z3.Bool
	ActionMatch    z3.Bool
	ResourceMatch  z3.Bool
	ConditionMatch z3.Bool

	AssertionName string
	NotModeled    []string
}

// TrustEdge records an "X can assume Y" relationship.
type TrustEdge struct {
	Assumer string
	Assumee string
}

// EncryptionEdge records that a resource is encrypted with a KMS key.
type EncryptionEdge struct {
	Resource string
	KMSKey   string
}

// CompiledInvariant is the Z3 form of one InvariantDefinition.
type CompiledInvariant struct {
	ID         string
	Severity   string
	Properties []string
	Predicate  func(env *InvariantEnv) z3.Bool
}

// InvariantEnv binds property paths to symbolic Z3 values.
type InvariantEnv struct {
	Ctx          *z3.Context
	StringSort   z3.Sort
	BoolSort     z3.Sort
	StringValues map[string]z3.Uninterpreted
	BoolValues   map[string]z3.Bool
}

// String returns the symbolic string-typed value bound to path.
func (e *InvariantEnv) String(path string) z3.Uninterpreted {
	if v, ok := e.StringValues[path]; ok {
		return v
	}
	v := e.Ctx.Const("prop:"+path, e.StringSort).(z3.Uninterpreted)
	if e.StringValues == nil {
		e.StringValues = map[string]z3.Uninterpreted{}
	}
	e.StringValues[path] = v
	return v
}

// Bool returns the symbolic boolean bound to path.
func (e *InvariantEnv) Bool(path string) z3.Bool {
	if v, ok := e.BoolValues[path]; ok {
		return v
	}
	v := e.Ctx.BoolConst("prop:" + path)
	if e.BoolValues == nil {
		e.BoolValues = map[string]z3.Bool{}
	}
	e.BoolValues[path] = v
	return v
}

// FromString returns a Z3 uninterpreted constant for a literal string.
func (e *InvariantEnv) FromString(s string) z3.Uninterpreted {
	key := "str:" + s
	if v, ok := e.StringValues[key]; ok {
		return v
	}
	v := e.Ctx.Const(key, e.StringSort).(z3.Uninterpreted)
	if e.StringValues == nil {
		e.StringValues = map[string]z3.Uninterpreted{}
	}
	e.StringValues[key] = v
	return v
}

// Compile translates the Stave exports into a CompiledModel.
func Compile(exports *Exports) (*CompiledModel, error) {
	if exports == nil {
		return nil, fmt.Errorf("compiler: exports is nil")
	}
	cfg := z3.NewContextConfig()
	ctx := z3.NewContext(cfg)
	model := &CompiledModel{
		Ctx:        ctx,
		Invariants: map[string]CompiledInvariant{},
	}

	model.collectUniverse(exports)

	if err := model.compilePolicies(exports.Policies); err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}
	if err := model.compileGraph(exports.Graph, exports.Policies); err != nil {
		return nil, fmt.Errorf("compile graph: %w", err)
	}
	if err := model.compileInvariants(exports.Invariants); err != nil {
		return nil, fmt.Errorf("compile invariants: %w", err)
	}
	return model, nil
}

func (m *CompiledModel) collectUniverse(exports *Exports) {
	m.PrincipalSort = m.Ctx.UninterpretedSort("Principal")
	m.ActionSort = m.Ctx.UninterpretedSort("Action")
	m.ResourceSort = m.Ctx.UninterpretedSort("Resource")

	m.Principals = map[string]z3.Uninterpreted{}
	m.Actions = map[string]z3.Uninterpreted{}
	m.Resources = map[string]z3.Uninterpreted{}

	addPrincipal := func(p string) {
		if p == "" || p == "*" {
			return
		}
		if _, ok := m.Principals[p]; ok {
			return
		}
		m.Principals[p] = m.Ctx.Const("p:"+p, m.PrincipalSort).(z3.Uninterpreted)
	}
	addAction := func(a string) {
		if a == "" || a == "*" {
			return
		}
		if _, ok := m.Actions[a]; ok {
			return
		}
		m.Actions[a] = m.Ctx.Const("a:"+a, m.ActionSort).(z3.Uninterpreted)
	}
	addResource := func(r string) {
		if r == "" || r == "*" {
			return
		}
		if _, ok := m.Resources[r]; ok {
			return
		}
		m.Resources[r] = m.Ctx.Const("r:"+r, m.ResourceSort).(z3.Uninterpreted)
	}

	walkDoc := func(stmts []PolicyStatement, sourceAsset string) {
		addResource(sourceAsset)
		for i := range stmts {
			s := &stmts[i]
			for _, p := range s.Principals {
				addPrincipal(stripCategoryPrefix(p))
			}
			for _, p := range s.NotPrincipals {
				addPrincipal(stripCategoryPrefix(p))
			}
			for _, a := range s.Actions {
				addAction(a)
			}
			for _, a := range s.NotActions {
				addAction(a)
			}
			for _, r := range s.Resources {
				addResource(r)
			}
			for _, r := range s.NotResources {
				addResource(r)
			}
		}
	}

	if exports.Policies != nil {
		for i := range exports.Policies.ResourcePolicies {
			d := &exports.Policies.ResourcePolicies[i]
			walkDoc(d.Statements, d.SourceAssetID)
		}
		for i := range exports.Policies.KMSKeyPolicies {
			d := &exports.Policies.KMSKeyPolicies[i]
			walkDoc(d.Statements, d.SourceAssetID)
		}
		for i := range exports.Policies.TrustPolicies {
			d := &exports.Policies.TrustPolicies[i]
			walkDoc(d.Statements, d.SourceAssetID)
			addPrincipal(d.SourceAssetID)
		}
		for _, edge := range exports.Policies.AssetRelationships {
			addPrincipal(edge.FromAssetID)
			addResource(edge.ToAssetID)
		}
	}
	if exports.Graph != nil {
		for i := range exports.Graph.Assets {
			addResource(exports.Graph.Assets[i].ID)
		}
	}
}

func stripCategoryPrefix(p string) string {
	for _, prefix := range []string{"AWS:", "Service:", "Federated:", "CanonicalUser:"} {
		if len(p) > len(prefix) && p[:len(prefix)] == prefix {
			return p[len(prefix):]
		}
	}
	return p
}
