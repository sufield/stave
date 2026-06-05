package schema

import "testing"

// Test_RedGate_HasPathTypoPrefix pins the intended behavior described in
// hasPath's guard comment: a schema-author path that "didn't start with
// 'properties.'" — including the dot-omitted typo "propertiesfoo" — must be
// treated as an unhandled shape and reported as MISSING (return false), so the
// author sees the warning. The current operator-precedence bug at
// schema.go:140 lets such a typo fall through and be looked up as a literal
// top-level key, returning TRUE and silently treating a malformed schema path
// as a satisfied requirement.
func Test_RedGate_HasPathTypoPrefix(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("hasPath panicked: %v", r)
		}
	}()

	// Dot-omitted typo: TrimPrefix("propertiesfoo","properties.") leaves it
	// unchanged so path==dotted, but HasPrefix(dotted,"properties") is true,
	// so the guard does NOT fire and the path is looked up as the literal
	// top-level key "propertiesfoo", which is present and non-nil.
	got := hasPath(map[string]any{"propertiesfoo": 1}, "propertiesfoo")

	if got {
		t.Fatalf("hasPath(propertiesfoo typo) = true; want false " +
			"(malformed schema path must be treated as missing so the author is warned)")
	}
}
