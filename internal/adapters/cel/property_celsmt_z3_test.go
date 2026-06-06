//go:build z3

// Phase 3: CEL ↔ SMT agreement, discharged with Z3.
//
// IMPORTANT SCOPE NOTE (flagged in Phase 0): Stave has no generic
// predicate→SMT-query TRANSLATOR that it discharges to a verdict. The smt2
// export is facts-only plus a forbidden_state block consumed by EXTERNAL
// tooling, and the only end-to-end Z3 discharge in the repo is hand-coded per
// example. Per-asset predicate evaluation is moreover GROUND boolean logic, so
// Z3 adds no reasoning over unknowns there.
//
// So this property does the achievable, on-point form of the task's intent: it
// treats Z3 as an INDEPENDENT ORACLE for predicate-operator semantics. The same
// generated predicate is (a) evaluated through Stave's real CEL path — the
// engine's truth source — and (b) translated to SMT-LIB here and discharged
// with the z3 binary. A divergence is a CEL operator-semantics bug, which is
// exactly the failure the task warns about: a CEL/SMT mismatch means the facts
// Stave exports to a reasoning engine would disagree with the verdicts it
// renders internally.
//
// Build-tagged `z3` and skipped unless the z3 binary is on PATH, so CI is never
// made flaky. Run with:
//
//	PATH="$PATH:$HOME/.local/bin" go test -tags 'stavedev z3' \
//	  -run TestProperty_CELMatchesZ3 ./internal/adapters/cel/
//
// Scoped to the cleanly-encodable operator subset: eq/ne on a Bool field,
// eq/ne/gt/lt/gte/lte on an Int field, composed with any/all (incl. one nested
// level). Strings, lists, present/missing, and cross-field operators are out of
// scope (their faithful SMT encoding is a separate, larger effort) and are
// deliberately not generated.
package cel_test

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// --- intermediate predicate AST: the single source from which we derive BOTH
// the controldef.UnsafePredicate (for CEL) and the SMT-LIB string (for Z3), so
// the two sides provably encode the same predicate. ---

type leaf struct {
	isBool  bool
	op      predicate.Operator
	valBool bool
	valInt  int
}

type ruleNode struct {
	leaf   *leaf
	nested *node
}

type node struct {
	logic string // "any" (OR) or "all" (AND)
	rules []ruleNode
}

func genLeaf(rt *rapid.T) *leaf {
	if rapid.Bool().Draw(rt, "is_bool_field") {
		op := rapid.SampledFrom([]predicate.Operator{predicate.OpEq, predicate.OpNe}).Draw(rt, "bool_op")
		return &leaf{isBool: true, op: op, valBool: rapid.Bool().Draw(rt, "bool_val")}
	}
	op := rapid.SampledFrom([]predicate.Operator{
		predicate.OpEq, predicate.OpNe, predicate.OpGt, predicate.OpLt, predicate.OpGte, predicate.OpLte,
	}).Draw(rt, "int_op")
	return &leaf{isBool: false, op: op, valInt: rapid.IntRange(0, 4).Draw(rt, "int_val")}
}

func genNode(rt *rapid.T, depth int) node {
	logic := "all"
	if rapid.Bool().Draw(rt, "logic_any") {
		logic = "any"
	}
	n := rapid.IntRange(1, 3).Draw(rt, "rule_count")
	rules := make([]ruleNode, n)
	for i := range rules {
		if depth < 1 && rapid.IntRange(0, 3).Draw(rt, "nest") == 0 {
			sub := genNode(rt, depth+1)
			rules[i] = ruleNode{nested: &sub}
		} else {
			rules[i] = ruleNode{leaf: genLeaf(rt)}
		}
	}
	return node{logic: logic, rules: rules}
}

// --- AST -> controldef.UnsafePredicate ---

func fieldOf(l leaf) predicate.FieldPath {
	if l.isBool {
		return predicate.NewFieldPath("properties.b")
	}
	return predicate.NewFieldPath("properties.n")
}

func leafToRule(l leaf) policy.PredicateRule {
	r := policy.PredicateRule{Field: fieldOf(l), Op: l.op}
	if l.isBool {
		r.Value = policy.NewOperand(l.valBool)
	} else {
		r.Value = policy.NewOperand(l.valInt)
	}
	return r
}

func nodeRules(n node) []policy.PredicateRule {
	out := make([]policy.PredicateRule, len(n.rules))
	for i, r := range n.rules {
		switch {
		case r.leaf != nil:
			out[i] = leafToRule(*r.leaf)
		case r.nested.logic == "any":
			out[i] = policy.PredicateRule{Any: nodeRules(*r.nested)}
		default:
			out[i] = policy.PredicateRule{All: nodeRules(*r.nested)}
		}
	}
	return out
}

func nodeToPredicate(n node) policy.UnsafePredicate {
	if n.logic == "any" {
		return policy.UnsafePredicate{Any: nodeRules(n)}
	}
	return policy.UnsafePredicate{All: nodeRules(n)}
}

// --- AST -> SMT-LIB formula ---

func leafToSMT(l leaf) string {
	if l.isBool {
		v := strconv.FormatBool(l.valBool)
		if l.op == predicate.OpNe {
			return "(not (= b " + v + "))"
		}
		return "(= b " + v + ")"
	}
	v := strconv.Itoa(l.valInt)
	switch l.op {
	case predicate.OpNe:
		return "(not (= n " + v + "))"
	case predicate.OpGt:
		return "(> n " + v + ")"
	case predicate.OpLt:
		return "(< n " + v + ")"
	case predicate.OpGte:
		return "(>= n " + v + ")"
	case predicate.OpLte:
		return "(<= n " + v + ")"
	default: // OpEq
		return "(= n " + v + ")"
	}
}

func nodeToSMT(n node) string {
	parts := make([]string, len(n.rules))
	for i, r := range n.rules {
		if r.leaf != nil {
			parts[i] = leafToSMT(*r.leaf)
		} else {
			parts[i] = nodeToSMT(*r.nested)
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	conn := "and"
	if n.logic == "any" {
		conn = "or"
	}
	return "(" + conn + " " + strings.Join(parts, " ") + ")"
}

// dischargeZ3 pins b and n to the asset's values, asserts the predicate, and
// returns whether the conjunction is satisfiable — i.e. whether the predicate
// holds at those values.
func dischargeZ3(t *testing.T, z3 string, bv bool, nv int, formula string) bool {
	t.Helper()
	smt := strings.Join([]string{
		"(declare-const b Bool)",
		"(declare-const n Int)",
		"(assert (= b " + strconv.FormatBool(bv) + "))",
		"(assert (= n " + strconv.Itoa(nv) + "))",
		"(assert " + formula + ")",
		"(check-sat)",
		"",
	}, "\n")
	cmd := exec.Command(z3, "-smt2", "/dev/stdin")
	cmd.Stdin = strings.NewReader(smt)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("z3 invocation failed: %v\nsmt:\n%s", err, smt)
	}
	res := strings.TrimSpace(string(out))
	switch {
	case strings.HasPrefix(res, "unsat"):
		return false
	case strings.HasPrefix(res, "sat"):
		return true
	default:
		t.Fatalf("z3 returned neither sat nor unsat: %q\nsmt:\n%s", res, smt)
		return false
	}
}

// TestProperty_CELMatchesZ3 asserts that for every generated predicate and
// asset, Stave's CEL verdict equals the Z3 verdict on the same predicate.
func TestProperty_CELMatchesZ3(t *testing.T) {
	z3, err := exec.LookPath("z3")
	if err != nil {
		if _, statErr := os.Stat(os.Getenv("HOME") + "/.local/bin/z3"); statErr == nil {
			z3 = os.Getenv("HOME") + "/.local/bin/z3"
		} else {
			t.Skip("z3 binary not found on PATH; skipping CEL↔SMT agreement (build tag z3 is set but the solver is absent)")
		}
	}

	eval, err := stavecel.NewPredicateEval()
	if err != nil {
		t.Fatalf("NewPredicateEval: %v", err)
	}

	rapid.Check(t, func(rt *rapid.T) {
		ast := genNode(rt, 0)
		pred := nodeToPredicate(ast)
		formula := nodeToSMT(ast)

		bv := rapid.Bool().Draw(rt, "asset_b")
		nv := rapid.IntRange(0, 4).Draw(rt, "asset_n")
		a := asset.Asset{
			ID:         "z3-prop",
			Type:       "test_resource",
			Properties: map[string]any{"b": bv, "n": nv},
		}

		verdictCEL, evalErr := eval(policy.ControlDefinition{ID: "CTL.PROP.Z3.001", UnsafePredicate: pred}, a, nil)
		if evalErr != nil {
			rt.Fatalf("CEL eval error on a well-formed predicate: %v\nformula: %s\nasset: b=%v n=%d", evalErr, formula, bv, nv)
		}

		verdictZ3 := dischargeZ3(t, z3, bv, nv, formula)

		if verdictCEL != verdictZ3 {
			rt.Fatalf("CEL and Z3 disagree on the same predicate:\n"+
				"  predicate (SMT): %s\n  asset: b=%v n=%d\n  CEL=%v  Z3=%v",
				formula, bv, nv, verdictCEL, verdictZ3)
		}
	})
}
