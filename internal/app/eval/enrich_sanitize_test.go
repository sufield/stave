package eval

import (
	"encoding/json"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

type noopSanitizer struct{}

func (noopSanitizer) ID(s string) string    { return s }
func (noopSanitizer) Path(s string) string  { return s }
func (noopSanitizer) Value(s string) string { return s }

func TestSanitizeActualValue_UnsignedIntegers(t *testing.T) {
	s := noopSanitizer{}

	tests := []struct {
		name  string
		input any
		want  any
	}{
		{"uint", uint(42), uint(42)},
		{"uint64", uint64(999), uint64(999)},
		{"uint32", uint32(7), uint32(7)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeActualValue(tc.input, s)
			if got == kernel.Redacted {
				t.Errorf("sanitizeActualValue(%v) = %v, want %v (unsigned int was redacted)", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeSlice_EmptyReturnsEmptyNotNil(t *testing.T) {
	s := noopSanitizer{}
	got := sanitizeSlice([]string{}, s)

	if got == nil {
		t.Fatal("sanitizeSlice([]) returned nil, want non-nil empty slice")
	}

	b, _ := json.Marshal(got)
	if string(b) != "[]" {
		t.Errorf("JSON marshal of empty sanitized slice = %s, want []", b)
	}
}

// TestSanitizeSlice_NilStaysNil pins the new contract: a nil input
// must return nil. JSON encoders emit `null` for nil and `[]` for
// empty; the earlier shape collapsed nil to `[]`, hiding the
// "field was deliberately unset" signal from downstream consumers.
func TestSanitizeSlice_NilStaysNil(t *testing.T) {
	s := noopSanitizer{}
	got := sanitizeSlice[string](nil, s)
	if got != nil {
		t.Errorf("sanitizeSlice(nil) = %v, want nil", got)
	}
	b, _ := json.Marshal(got)
	if string(b) != "null" {
		t.Errorf("JSON marshal of nil sanitized slice = %s, want null", b)
	}
}
