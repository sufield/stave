package predicate

import "testing"

// TestIsSupported verifies the operator registry.
func TestIsSupported(t *testing.T) {
	// All supported operators should return true
	supported := []string{
		"eq", "ne", "gt", "lt", "gte", "lte", "missing", "present", "in",
		"list_empty", "not_subset_of_field", "neq_field", "not_in_field",
		"contains", "any_match",
	}
	for _, op := range supported {
		if !IsSupported(op) {
			t.Errorf("IsSupported(%q) = false, want true", op)
		}
	}

	// Unknown operators should return false
	unsupported := []string{"unknown", ""}
	for _, op := range unsupported {
		if IsSupported(op) {
			t.Errorf("IsSupported(%q) = true, want false", op)
		}
	}
}

// TestOperatorFailClosedBehavior tests that operators fail closed (return false) on invalid input.
func TestOperatorFailClosedBehavior(t *testing.T) {
	tests := []struct {
		name string
		a, b any
	}{
		{"gt with string vs int", "abc", 42},
		{"gt with nil vs int", nil, 42},
		{"gt with int vs nil", 42, nil},
		{"gt with string vs string", "abc", "def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if GreaterThan(tt.a, tt.b) {
				t.Errorf("GreaterThan(%v, %v) = true, want false (fail closed)", tt.a, tt.b)
			}
		})
	}
}

// TestEqualValuesTypes tests EqualValues with various type combinations.
func TestEqualValuesTypes(t *testing.T) {
	tests := []struct {
		name string
		a, b any
		want bool
	}{
		{"bool true==true", true, true, true},
		{"bool true==false", true, false, false},
		{"bool true==string true", true, "true", true},
		{"bool true==string TRUE", true, "TRUE", true},
		{"bool true==string 1", true, "1", true},
		{"bool false==string false with spaces", false, " false ", true},
		{"bool false==string 0", false, "0", true},
		{"string equal", "hello", "hello", true},
		{"string equal case-insensitive", "AES256", "aes256", true},
		{"string equal trimmed", " Enabled ", "enabled", true},
		{"string different", "hello", "world", false},
		{"int equal", 42, 42, true},
		{"int different", 42, 43, false},
		{"float equal", 3.14, 3.14, true},
		{"int vs float equal", 42, 42.0, true},
		{"numeric string vs int equal", "80", 80, true},
		{"numeric string trimmed vs int equal", " 80 ", 80, true},
		{"type mismatch", "forty-two", 42, false},
		{"list mismatch does not panic", []any{1}, []any{1}, false},
		{"map mismatch does not panic", map[string]any{"k": 1}, map[string]any{"k": 1}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EqualValues(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("EqualValues(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestIsEmptyValue tests the missing/empty value detection.
func TestIsEmptyValue(t *testing.T) {
	s := "hello"
	empty := ""

	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"nil is empty", nil, true},
		{"empty string is empty", "", true},
		{"whitespace string is empty", "   ", true},
		{"non-empty string is not empty", "hello", false},
		{"nil pointer is empty", (*string)(nil), true},
		{"empty string pointer is empty", &empty, true},
		{"non-empty string pointer is not empty", &s, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEmptyValue(tt.value)
			if got != tt.want {
				t.Errorf("IsEmptyValue(%v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestIsEmptyList tests the list empty detection.
func TestIsEmptyList(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"nil is empty", nil, true},
		{"empty []interface{} is empty", []any{}, true},
		{"non-empty []interface{} is not empty", []any{"a", "b"}, false},
		{"empty []string is empty", []string{}, true},
		{"non-empty []string is not empty", []string{"a", "b"}, false},
		{"non-list is treated as empty", 42, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEmptyList(tt.value)
			if got != tt.want {
				t.Errorf("IsEmptyList(%v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestValueInList tests the "in" operator.
func TestValueInList(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		list   any
		wantIn bool
	}{
		{"string in []interface{}", "a", []any{"a", "b", "c"}, true},
		{"string not in []interface{}", "x", []any{"a", "b", "c"}, false},
		{"string in []string", "a", []string{"a", "b", "c"}, true},
		{"string not in []string", "x", []string{"a", "b", "c"}, false},
		{"string in empty list", "a", []any{}, false},
		{"int in list", 42, []any{1, 42, 100}, true},
		{"int not matched in []string", 42, []string{"42"}, false},
		{"string []any remains exact", "A", []any{"a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValueInList(tt.value, tt.list)
			if got != tt.wantIn {
				t.Errorf("ValueInList(%v, %v) = %v, want %v", tt.value, tt.list, got, tt.wantIn)
			}
		})
	}
}

// TestListHasElementsNotIn tests the not_subset_of_field operator.
func TestListHasElementsNotIn(t *testing.T) {
	tests := []struct {
		name  string
		listA any
		listB any
		want  bool
	}{
		{"subset", []string{"a", "b"}, []string{"a", "b", "c"}, false},
		{"has extra", []string{"a", "d"}, []string{"a", "b", "c"}, true},
		{"empty listA", []string{}, []string{"a", "b"}, false},
		{"empty listB", []string{"a"}, []string{}, true},
		{"invalid listB", []string{"a"}, 42, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ListHasElementsNotIn(tt.listA, tt.listB)
			if got != tt.want {
				t.Errorf("ListHasElementsNotIn(%v, %v) = %v, want %v", tt.listA, tt.listB, got, tt.want)
			}
		})
	}
}

// TestListSupportedDocumented ensures all operators are documented.
func TestListSupportedDocumented(t *testing.T) {
	expected := map[string]string{
		"eq":                  "Equals (string, bool, numeric)",
		"ne":                  "Not equals (string, bool, numeric)",
		"gt":                  "Greater than (numeric)",
		"lt":                  "Less than (numeric)",
		"gte":                 "Greater than or equal (numeric)",
		"lte":                 "Less than or equal (numeric)",
		"missing":             "Field absent, nil, or empty",
		"present":             "Field exists and non-empty",
		"in":                  "Value in list",
		"list_empty":          "List field is empty or missing",
		"not_subset_of_field": "List contains elements not in another field",
		"neq_field":           "Value not equal to another field",
		"not_in_field":        "Value not in list specified by another field",
		"contains":            "String contains substring",
		"any_match":           "Any element in array matches nested predicate",
	}

	ops := ListSupported()
	if len(ops) != len(expected) {
		t.Errorf("ListSupported() has %d entries, expected %d", len(ops), len(expected))
	}

	for _, op := range ops {
		if _, ok := expected[op]; !ok {
			t.Errorf("Operator %q is not documented", op)
		}
	}
}

// TestStringContains tests the StringContains helper function.
func TestStringContains(t *testing.T) {
	tests := []struct {
		name string
		a, b any
		want bool
	}{
		{"substring match", "hello world", "world", true},
		{"no match", "hello", "xyz", false},
		{"exact match", "hello", "hello", true},
		{"empty substring", "hello", "", true},
		{"non-string field", 42, "world", false},
		{"non-string value", "hello", 42, false},
		{"both non-string", 42, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringContains(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("StringContains(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
