package predicate

import "testing"

func TestOperator_IsStandard(t *testing.T) {
	standard := []Operator{OpEq, OpNe, OpGt, OpLt, OpGte, OpLte, OpMissing, OpPresent, OpIn, OpListEmpty, OpContains}
	for _, op := range standard {
		if !op.IsStandard() {
			t.Errorf("%q.IsStandard() = false, want true", op)
		}
	}

	nonStandard := []Operator{OpNotSubsetOfField, OpNeqField, OpNotInField, OpAnyMatch, "unknown"}
	for _, op := range nonStandard {
		if op.IsStandard() {
			t.Errorf("%q.IsStandard() = true, want false", op)
		}
	}
}

func TestOperator_IsFieldRef(t *testing.T) {
	fieldRef := []Operator{OpNeqField, OpNotInField, OpNotSubsetOfField}
	for _, op := range fieldRef {
		if !op.IsFieldRef() {
			t.Errorf("%q.IsFieldRef() = false, want true", op)
		}
	}

	nonFieldRef := []Operator{OpEq, OpNe, OpMissing, OpAnyMatch, "unknown"}
	for _, op := range nonFieldRef {
		if op.IsFieldRef() {
			t.Errorf("%q.IsFieldRef() = true, want false", op)
		}
	}
}

func TestOperator_IsPresenceBased(t *testing.T) {
	if !OpMissing.IsPresenceBased() {
		t.Error("OpMissing.IsPresenceBased() = false, want true")
	}
	if !OpPresent.IsPresenceBased() {
		t.Error("OpPresent.IsPresenceBased() = false, want true")
	}
	if OpEq.IsPresenceBased() {
		t.Error("OpEq.IsPresenceBased() = true, want false")
	}
}

func TestOperator_RequiresNestedPredicate(t *testing.T) {
	if !OpAnyMatch.RequiresNestedPredicate() {
		t.Error("OpAnyMatch.RequiresNestedPredicate() = false, want true")
	}
	if OpEq.RequiresNestedPredicate() {
		t.Error("OpEq.RequiresNestedPredicate() = true, want false")
	}
}

func TestIsSupported(t *testing.T) {
	supported := []Operator{
		OpEq, OpNe, OpGt, OpLt, OpGte, OpLte,
		OpMissing, OpPresent, OpIn, OpListEmpty,
		OpNotSubsetOfField, OpNeqField, OpNotInField,
		OpContains, OpAnyMatch,
	}
	for _, op := range supported {
		if !IsSupported(op) {
			t.Errorf("IsSupported(%q) = false, want true", op)
		}
	}

	if IsSupported("unknown") {
		t.Error("IsSupported(\"unknown\") = true, want false")
	}
}

func TestListSupported(t *testing.T) {
	ops := ListSupported()
	if len(ops) != 15 {
		t.Fatalf("ListSupported() returned %d operators, want 15", len(ops))
	}

	// Verify sorted order.
	for i := 1; i < len(ops); i++ {
		if string(ops[i-1]) >= string(ops[i]) {
			t.Errorf("ListSupported() not sorted: %q >= %q at index %d", ops[i-1], ops[i], i)
		}
	}
}
