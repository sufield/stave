package eval

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

// stubSanitizer routes every string through the same prefix transform
// so tests can assert that strings actually flowed through s.Value().
type stubSanitizer struct{}

func (stubSanitizer) ID(id string) string   { return "ID:" + id }
func (stubSanitizer) Path(p string) string  { return "PATH:" + p }
func (stubSanitizer) Value(v string) string { return "VAL:" + v }

func TestSanitizeActualValue_BooleanPreserved(t *testing.T) {
	for _, b := range []bool{true, false} {
		got := sanitizeActualValue(b, stubSanitizer{})
		if got != b {
			t.Errorf("sanitizeActualValue(%v) = %v, want %v (boolean preserved)", b, got, b)
		}
	}
}

func TestSanitizeActualValue_NumericPreserved(t *testing.T) {
	cases := []any{42, int64(7), 3.14}
	for _, v := range cases {
		got := sanitizeActualValue(v, stubSanitizer{})
		if got != v {
			t.Errorf("sanitizeActualValue(%v) = %v, want %v (numeric preserved)", v, got, v)
		}
	}
}

func TestSanitizeActualValue_NilPreserved(t *testing.T) {
	got := sanitizeActualValue(nil, stubSanitizer{})
	if got != nil {
		t.Errorf("sanitizeActualValue(nil) = %v, want nil", got)
	}
}

func TestSanitizeActualValue_StringRoutedThroughSanitizer(t *testing.T) {
	got := sanitizeActualValue("my-bucket-arn", stubSanitizer{})
	want := "VAL:my-bucket-arn"
	if got != want {
		t.Errorf("sanitizeActualValue(string) = %v, want %v (must route through s.Value)", got, want)
	}
}

func TestSanitizeActualValue_StringSliceElementWise(t *testing.T) {
	got := sanitizeActualValue([]string{"a", "b"}, stubSanitizer{})
	want := []string{"VAL:a", "VAL:b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sanitizeActualValue([]string) = %v, want %v", got, want)
	}
}

func TestSanitizeActualValue_AnySliceMixedTypes(t *testing.T) {
	got := sanitizeActualValue([]any{"a", true, 42, nil}, stubSanitizer{})
	want := []any{"VAL:a", true, 42, nil}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sanitizeActualValue([]any) = %v, want %v", got, want)
	}
}

func TestSanitizeActualValue_MapRecursive(t *testing.T) {
	got := sanitizeActualValue(map[string]any{"id": "x", "count": 3, "active": true}, stubSanitizer{})
	want := map[string]any{"id": "VAL:x", "count": 3, "active": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sanitizeActualValue(map) = %v, want %v", got, want)
	}
}

func TestSanitizeActualValue_UnknownTypeFallsBackToRedacted(t *testing.T) {
	type customStruct struct{ X int }
	got := sanitizeActualValue(customStruct{X: 1}, stubSanitizer{})
	if got != kernel.Redacted {
		t.Errorf("sanitizeActualValue(custom struct) = %v, want %q (conservative fallback)", got, kernel.Redacted)
	}
}

// TestSanitizeActualValue_NamedStringRoutedLikePlainString pins the
// cache-determinism fix. Misconfiguration.ActualValue is `any`: a fresh
// evaluation carries a *named* string type (e.g. kernel.AssetType from the
// "asset type = X" predicate), but a value that round-trips through the
// content-addressed assessment cache is JSON-decoded back to a *plain*
// `string`. Before the fix the named type missed `case string` and fell to the
// conservative `default: Redacted` branch, so a cache MISS redacted a
// non-sensitive category to [SANITIZED] while a cache HIT showed it raw —
// non-deterministic, environment-dependent output. Both must now route through
// s.Value() identically.
func TestSanitizeActualValue_NamedStringRoutedLikePlainString(t *testing.T) {
	// kernel.AssetType is the concrete type that surfaced the bug.
	if got := sanitizeActualValue(kernel.AssetType("k8s_apiserver"), stubSanitizer{}); got != "VAL:k8s_apiserver" {
		t.Errorf("sanitizeActualValue(kernel.AssetType) = %v, want VAL:k8s_apiserver (named string must route through s.Value, not the Redacted default)", got)
	}
	// Any named string type behaves the same as the plain-string (cache-decoded) form.
	type customStr string
	if got := sanitizeActualValue(customStr("hello"), stubSanitizer{}); got != "VAL:hello" {
		t.Errorf("sanitizeActualValue(named string) = %v, want VAL:hello", got)
	}
}
