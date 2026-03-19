package predicate

import (
	"encoding/json"
	"testing"
)

// --- FieldPath tests ---

func TestNewFieldPath_SplitsParts(t *testing.T) {
	cases := []struct {
		input string
		parts []string
	}{
		{"properties.storage.kind", []string{"properties", "storage", "kind"}},
		{"type", []string{"type"}},
		{"a.b.c.d", []string{"a", "b", "c", "d"}},
		{"", nil},
	}
	for _, tc := range cases {
		fp := NewFieldPath(tc.input)
		if fp.String() != tc.input {
			t.Errorf("String() = %q, want %q", fp.String(), tc.input)
		}
		got := fp.Parts()
		if len(got) != len(tc.parts) {
			t.Errorf("Parts(%q) len = %d, want %d", tc.input, len(got), len(tc.parts))
			continue
		}
		for i := range got {
			if got[i] != tc.parts[i] {
				t.Errorf("Parts(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.parts[i])
			}
		}
	}
}

func TestFieldPath_IsZero(t *testing.T) {
	if !NewFieldPath("").IsZero() {
		t.Error("empty path should be zero")
	}
	if NewFieldPath("x").IsZero() {
		t.Error("non-empty path should not be zero")
	}
}

func TestFieldPath_TrimPrefix(t *testing.T) {
	fp := NewFieldPath("properties.storage.kind")
	if got := fp.TrimPrefix("properties."); got != "storage.kind" {
		t.Errorf("TrimPrefix = %q, want %q", got, "storage.kind")
	}
	if got := fp.TrimPrefix("missing."); got != "properties.storage.kind" {
		t.Errorf("TrimPrefix(missing) = %q, want original", got)
	}
}

func TestFieldPath_JSONRoundTrip(t *testing.T) {
	original := NewFieldPath("properties.storage.kind")
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `"properties.storage.kind"` {
		t.Errorf("marshal = %s", data)
	}

	var restored FieldPath
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.String() != original.String() {
		t.Errorf("round-trip: got %q, want %q", restored.String(), original.String())
	}
	if len(restored.Parts()) != 3 {
		t.Errorf("round-trip parts len = %d, want 3", len(restored.Parts()))
	}
}

// --- Operator tests ---

func TestOperator_IsStandard(t *testing.T) {
	standard := []Operator{OpEq, OpNe, OpGt, OpLt, OpGte, OpLte, OpMissing, OpPresent, OpIn, OpListEmpty, OpContains}
	for _, op := range standard {
		if !op.IsStandard() {
			t.Errorf("%s should be standard", op)
		}
	}
	nonStandard := []Operator{OpNeqField, OpNotInField, OpNotSubsetOfField, OpAnyMatch}
	for _, op := range nonStandard {
		if op.IsStandard() {
			t.Errorf("%s should not be standard", op)
		}
	}
}

func TestOperator_IsFieldRef(t *testing.T) {
	fieldRefs := []Operator{OpNeqField, OpNotInField, OpNotSubsetOfField}
	for _, op := range fieldRefs {
		if !op.IsFieldRef() {
			t.Errorf("%s should be field ref", op)
		}
	}
	if OpEq.IsFieldRef() {
		t.Error("eq should not be field ref")
	}
}

func TestOperator_IsPresenceBased(t *testing.T) {
	if !OpMissing.IsPresenceBased() {
		t.Error("missing should be presence-based")
	}
	if !OpPresent.IsPresenceBased() {
		t.Error("present should be presence-based")
	}
	if OpEq.IsPresenceBased() {
		t.Error("eq should not be presence-based")
	}
}

func TestOperator_RequiresNestedPredicate(t *testing.T) {
	if !OpAnyMatch.RequiresNestedPredicate() {
		t.Error("any_match should require nested predicate")
	}
	if OpEq.RequiresNestedPredicate() {
		t.Error("eq should not require nested predicate")
	}
}

func TestIsSupported(t *testing.T) {
	for _, op := range ListSupported() {
		if !IsSupported(op) {
			t.Errorf("%s should be supported", op)
		}
	}
	if IsSupported(Operator("bogus")) {
		t.Error("bogus should not be supported")
	}
}

func TestListSupported_ContainsAllOperators(t *testing.T) {
	ops := ListSupported()
	if len(ops) != 15 {
		t.Errorf("expected 15 operators, got %d", len(ops))
	}
	// Verify sorted
	for i := 1; i < len(ops); i++ {
		if string(ops[i]) < string(ops[i-1]) {
			t.Errorf("not sorted: %s before %s", ops[i-1], ops[i])
		}
	}
}

// --- ParamRef tests ---

func TestParamRef_StringAndIsZero(t *testing.T) {
	var zero ParamRef
	if !zero.IsZero() {
		t.Error("zero ParamRef should be zero")
	}
	if zero.String() != "" {
		t.Error("zero ParamRef String should be empty")
	}

	ref := ParamRef("max_retention")
	if ref.IsZero() {
		t.Error("non-zero ParamRef should not be zero")
	}
	if ref.String() != "max_retention" {
		t.Errorf("String() = %q", ref.String())
	}
}
