// Package compiler translates Stave's typed export structs into
// Z3 assertions. The translation is split across files by export
// kind: policy.go handles PolicyExport, graph.go handles
// GraphExport, invariant.go handles InvariantExport. compiler.go
// itself owns the shared CompiledModel + the top-level Compile
// entry point and the IAM evaluation order encoding.
package compiler

import (
	"fmt"
	"sort"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/experiments/z3-solver/loader"
	"github.com/sufield/stave/pkg/stave"
)

// CompiledModel holds the Z3 representation of a Stave assessment.
// IAM principals, actions, and resources are encoded as constants
// in three uninterpreted sorts. The universe of each sort is
// closed at compile time to the symbols actually referenced by the
// loaded snapshot — wildcards (Principal "*", Action "s3:*",
// Resource "arn:aws:s3:::b/*") are expanded against that finite
// universe rather than encoded as symbolic string operators, which
// the go-z3 binding does not expose.
//
// Compile-time wildcard expansion is sound for finite, closed
// universes (the analyst's "what is reachable in this snapshot?"
// question) and is the standard approach taken by AWS Zelkova's
// SMT model. It is unsound for "is there ANY future configuration
// that violates this property?" — see [InvariantEnv] for the
// open-universe variant the invariant-verify query uses.
type CompiledModel struct {
	Ctx *z3.Context

	PrincipalSort z3.Sort
	ActionSort    z3.Sort
	ResourceSort  z3.Sort

	Principals map[string]z3.Uninterpreted
	Actions    map[string]z3.Uninterpreted
	Resources  map[string]z3.Uninterpreted

	// Stmt is the catalogue of compiled policy statements. Queries
	// that need a per-statement view (the choke-point unsat-core
	// extractor) iterate this slice; the IAM-evaluation predicate
	// folds them into one boolean expression.
	Stmt []CompiledStatement

	// TrustEdges and EncryptionEdges are derived from the graph /
	// asset-relationship export. The IAM evaluator consults
	// EncryptionEdges to add a kms:Decrypt requirement when a read
	// targets an encrypted resource. TrustEdges drive the
	// assume-role reachability the graph compiler builds.
	TrustEdges      []TrustEdge
	EncryptionEdges []EncryptionEdge

	// Invariants is the catalogue of compiled invariant
	// definitions, keyed by control ID. Lookup is by string ID so
	// the invariant-verify query can address a specific control
	// without scanning.
	Invariants map[stave.ControlID]CompiledInvariant

	// evalVarsCache lazily caches the (P, A, R) symbolic triple
	// EvaluateAccess and every CompiledStatement match against.
	// Allocated on first call to evalVars.
	evalVarsCache *queryVars
}

// CompiledStatement is a Z3-ready view of one PolicyStatement.
// PrincipalMatch / ActionMatch / ResourceMatch are precomputed
// boolean expressions over the symbolic (P, A, R) variables the
// caller introduces — true when the symbolic value falls in the
// statement's authored set. ConditionFn returns the boolean
// expression representing "the statement's authored conditions
// are satisfied"; today's compiler treats unmodelled condition
// operators as trivially-satisfied and records them in NotModeled
// so the proof certificate surfaces the gap.
type CompiledStatement struct {
	SourceAssetID string
	PolicyType    string
	Sid           string
	Effect        string

	PrincipalMatch z3.Bool
	ActionMatch    z3.Bool
	ResourceMatch  z3.Bool
	ConditionMatch z3.Bool

	// AssertionName uniquely identifies this statement in unsat
	// cores ("policy:<asset>|<type>|<sid>|<idx>").
	AssertionName string

	NotModeled []string
}

// TrustEdge records an "X can assume Y" relationship the
// trust-policy export reported. Both endpoints are ARNs.
type TrustEdge struct {
	Assumer string
	Assumee string
}

// EncryptionEdge records that a resource is encrypted with a
// specific KMS key.
type EncryptionEdge struct {
	Resource string
	KMSKey   string
}

// CompiledInvariant is the Z3 form of one InvariantDefinition.
// Predicate, when invoked with a populated [InvariantEnv], returns
// the boolean expression "this configuration is unsafe per the
// control's predicate". Properties enumerates the property paths
// the predicate reads so callers can pre-bind concrete values
// from a snapshot before evaluating Predicate.
type CompiledInvariant struct {
	ID         stave.ControlID
	Severity   stave.Severity
	Properties []string
	Predicate  func(env *InvariantEnv) z3.Bool
}

// InvariantEnv binds property paths to symbolic Z3 values an
// invariant predicate evaluates over. Free strings are encoded as
// uninterpreted constants in a per-property sort — the predicate
// can compare two property values for equality, but the value
// universe is open (any constant satisfies the typing). This is
// the open-universe pendant of [CompiledModel]'s closed IAM
// universe.
type InvariantEnv struct {
	Ctx          *z3.Context
	StringSort   z3.Sort
	BoolSort     z3.Sort
	StringValues map[string]z3.Uninterpreted
	BoolValues   map[string]z3.Bool
}

// String returns the symbolic string-typed value bound to path,
// allocating a fresh uninterpreted constant on first reference.
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

// Bool returns the symbolic boolean bound to path, allocating a
// fresh boolean constant on first reference.
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

// FromString returns a Z3 uninterpreted constant representing the
// literal string s in the env's StringSort. Distinct strings get
// distinct constants — the env's "string equality" semantics flow
// from Z3's congruence closure over uninterpreted symbols.
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

// Compile translates the bundle of Stave exports into a
// CompiledModel. Order matters: collectUniverse builds the
// principal/action/resource sorts from every reference seen, so
// it must run before the per-export compilers.
func Compile(exports *loader.StaveExports) (*CompiledModel, error) {
	if exports == nil {
		return nil, fmt.Errorf("compiler: exports is nil")
	}
	cfg := z3.NewContextConfig()
	ctx := z3.NewContext(cfg)
	model := &CompiledModel{
		Ctx:        ctx,
		Invariants: map[stave.ControlID]CompiledInvariant{},
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

// collectUniverse enumerates every distinct principal, action, and
// resource referenced by the policy export and the graph and
// allocates a Z3 uninterpreted constant per distinct symbol. The
// sort universes stay closed: a query asking about a symbol the
// snapshot did not reference treats it as "not in the model" and
// falls back to a NotModeled annotation in the proof.
func (m *CompiledModel) collectUniverse(exports *loader.StaveExports) {
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

	walkDoc := func(stmts []stave.PolicyStatement, sourceAsset string) {
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
			addResource(string(exports.Graph.Assets[i].ID))
		}
	}
}

// stripCategoryPrefix removes the "AWS:" / "Service:" /
// "Federated:" category prefix the policy export emits on
// principals so the model universe is keyed on the bare ARN.
func stripCategoryPrefix(p string) string {
	for _, prefix := range []string{"AWS:", "Service:", "Federated:", "CanonicalUser:"} {
		if len(p) > len(prefix) && p[:len(prefix)] == prefix {
			return p[len(prefix):]
		}
	}
	return p
}

// SortedKeys returns the map keys in lexicographic order. Used by
// debug and proof-output paths so iteration produces stable output.
func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
