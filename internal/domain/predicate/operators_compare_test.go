package predicate

import "testing"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		op       Operator
		fieldVal any
		matchVal any
		want     bool
	}{
		{"eq bool-string", OpEq, true, "TRUE", true},
		{"ne bool-string inverse", OpNe, true, "TRUE", false},
		{"eq case-insensitive string", OpEq, "AES256", "aes256", true},
		{"ne case-insensitive string inverse", OpNe, "aws:kms", "AWS:KMS", false},
		{"gt numeric-string", OpGt, "100", 90, true},
		{"unknown op fail closed", Operator("custom"), 1, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.op, tt.fieldVal, tt.matchVal)
			if got != tt.want {
				t.Fatalf("Evaluate(%q, %v, %v)=%v, want %v", tt.op, tt.fieldVal, tt.matchVal, got, tt.want)
			}
		})
	}
}

func TestEvaluateOperatorDispatch(t *testing.T) {
	tests := []struct {
		name        string
		op          Operator
		fieldExists bool
		fieldValue  any
		compare     any
		wantResult  bool
		wantHandled bool
	}{
		{"eq true", OpEq, true, "a", "a", true, true},
		{"eq bool-string true", OpEq, true, true, "TRUE", true, true},
		{"ne bool-string false", OpNe, true, true, "TRUE", false, true},
		{"eq missing", OpEq, false, nil, "a", false, true},
		{"eq nil value present", OpEq, true, nil, "AES256", false, true},
		{"ne nil value present", OpNe, true, nil, "AES256", true, true},
		{"ne missing", OpNe, false, nil, "a", true, true},
		{"gt", OpGt, true, 3, 2, true, true},
		{"lt", OpLt, true, 1, 2, true, true},
		{"gte", OpGte, true, 2, 2, true, true},
		{"lte", OpLte, true, 2, 2, true, true},
		{"missing true", OpMissing, false, nil, true, true, true},
		{"missing false", OpMissing, true, "x", false, true, true},
		{"present true", OpPresent, true, "x", true, true, true},
		{"present false for empty", OpPresent, true, "", false, true, true},
		{"in true", OpIn, true, "a", []string{"a", "b"}, true, true},
		{"list_empty true for missing", OpListEmpty, false, nil, true, true, true},
		{"contains true", OpContains, true, "hello world", "world", true, true},
		{"context op delegated", OpAnyMatch, true, []any{}, map[string]any{}, false, false},
		{"unknown op", Operator("custom"), true, 1, 1, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotHandled := EvaluateOperator(tt.op, tt.fieldExists, tt.fieldValue, tt.compare)
			if gotResult != tt.wantResult || gotHandled != tt.wantHandled {
				t.Fatalf(
					"EvaluateOperator(%q, %v, %v, %v) = (%v, %v), want (%v, %v)",
					tt.op, tt.fieldExists, tt.fieldValue, tt.compare, gotResult, gotHandled, tt.wantResult, tt.wantHandled,
				)
			}
		})
	}
}

func TestNumericComparators(t *testing.T) {
	t.Run("less than", func(t *testing.T) {
		if !LessThan(1, 2) {
			t.Fatal("expected LessThan(1,2)=true")
		}
		if LessThan(2, 1) {
			t.Fatal("expected LessThan(2,1)=false")
		}
		if LessThan("x", 1) {
			t.Fatal("expected non-numeric LessThan to fail closed")
		}
	})

	t.Run("greater than or equal", func(t *testing.T) {
		if !GreaterThanOrEqual(2, 2) {
			t.Fatal("expected GreaterThanOrEqual(2,2)=true")
		}
		if GreaterThanOrEqual(1, 2) {
			t.Fatal("expected GreaterThanOrEqual(1,2)=false")
		}
		if GreaterThanOrEqual("x", 1) {
			t.Fatal("expected non-numeric GreaterThanOrEqual to fail closed")
		}
	})

	t.Run("less than or equal", func(t *testing.T) {
		if !LessThanOrEqual(2, 2) {
			t.Fatal("expected LessThanOrEqual(2,2)=true")
		}
		if LessThanOrEqual(3, 2) {
			t.Fatal("expected LessThanOrEqual(3,2)=false")
		}
		if LessThanOrEqual("x", 1) {
			t.Fatal("expected non-numeric LessThanOrEqual to fail closed")
		}
	})
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want float64
		ok   bool
	}{
		{"int", int(1), 1, true},
		{"int32", int32(12), 12, true},
		{"int64", int64(2), 2, true},
		{"uint", uint(3), 3, true},
		{"uint32", uint32(13), 13, true},
		{"uint64", uint64(4), 4, true},
		{"float32", float32(5.5), 5.5, true},
		{"float64", float64(6.5), 6.5, true},
		{"numeric string", "8080", 8080, true},
		{"numeric string trimmed", " 8080 ", 8080, true},
		{"string", "x", 0, false},
		{"nil", nil, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ToFloat64(tt.in)
			if ok != tt.ok {
				t.Fatalf("ToFloat64(%v) ok=%v, want %v", tt.in, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("ToFloat64(%v)=%v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
