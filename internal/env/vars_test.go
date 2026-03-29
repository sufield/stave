package env

import (
	"testing"
)

func TestAll_ReturnsAllEntries(t *testing.T) {
	entries := All()
	if len(entries) == 0 {
		t.Fatal("All() returned empty slice")
	}
	// Verify the count matches the internal registry.
	if len(entries) != len(all) {
		t.Fatalf("All() returned %d entries, want %d", len(entries), len(all))
	}
}

func TestAll_SortedByCategoryThenName(t *testing.T) {
	entries := All()
	for i := 1; i < len(entries); i++ {
		prev, curr := entries[i-1], entries[i]
		if prev.Category > curr.Category {
			t.Fatalf("entries not sorted by category: %q (%s) before %q (%s)",
				prev.Name, prev.Category, curr.Name, curr.Category)
		}
		if prev.Category == curr.Category && prev.Name > curr.Name {
			t.Fatalf("entries not sorted by name within category: %q before %q in category %q",
				prev.Name, curr.Name, prev.Category)
		}
	}
}

func TestAll_ReturnsIndependentCopy(t *testing.T) {
	a := All()
	b := All()
	if len(a) == 0 {
		t.Fatal("All() returned empty")
	}
	a[0].Name = "MUTATED"
	if b[0].Name == "MUTATED" {
		t.Error("All() returned shared slice; mutations propagated")
	}
}

func TestEntry_Value_Default(t *testing.T) {
	e := Entry{
		Name:         "STAVE_TEST_UNSET_VAR_12345",
		DefaultValue: "fallback",
	}
	// Ensure the env var is not set.
	t.Setenv("STAVE_TEST_UNSET_VAR_12345", "")
	if got := e.Value(); got != "fallback" {
		t.Errorf("Value() = %q, want %q (default)", got, "fallback")
	}
}

func TestEntry_Value_EnvOverride(t *testing.T) {
	e := Entry{
		Name:         "STAVE_TEST_VALUE_OVERRIDE",
		DefaultValue: "fallback",
	}
	t.Setenv("STAVE_TEST_VALUE_OVERRIDE", "custom")
	if got := e.Value(); got != "custom" {
		t.Errorf("Value() = %q, want %q (env override)", got, "custom")
	}
}

func TestEntry_Value_WhitespaceOnlyEnvReturnsDefault(t *testing.T) {
	e := Entry{
		Name:         "STAVE_TEST_WHITESPACE_ONLY",
		DefaultValue: "default",
	}
	t.Setenv("STAVE_TEST_WHITESPACE_ONLY", "   ")
	if got := e.Value(); got != "default" {
		t.Errorf("Value() = %q, want %q (whitespace-only env treated as unset)", got, "default")
	}
}

func TestEntry_IsTrue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"1 is true", "1", true},
		{"true is true", "true", true},
		{"TRUE is true", "TRUE", true},
		{"True is true", "True", true},
		{"t is true", "t", true},
		{"0 is false", "0", false},
		{"false is false", "false", false},
		{"empty is false", "", false},
		{"random string is false", "yes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Entry{Name: "STAVE_TEST_IS_TRUE"}
			t.Setenv("STAVE_TEST_IS_TRUE", tt.value)
			if got := e.IsTrue(); got != tt.want {
				t.Errorf("IsTrue() with value %q = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestEntry_IsTrue_Unset(t *testing.T) {
	e := Entry{Name: "STAVE_TEST_IS_TRUE_UNSET_99999"}
	// Don't set the env var.
	t.Setenv("STAVE_TEST_IS_TRUE_UNSET_99999", "")
	if got := e.IsTrue(); got {
		t.Error("IsTrue() for unset env var should be false")
	}
}

func TestKnownEntries_HaveNonEmptyName(t *testing.T) {
	for _, e := range All() {
		if e.Name == "" {
			t.Error("entry with empty Name found")
		}
		if e.Description == "" {
			t.Errorf("entry %q has empty Description", e.Name)
		}
		if e.Category == "" {
			t.Errorf("entry %q has empty Category", e.Name)
		}
	}
}
