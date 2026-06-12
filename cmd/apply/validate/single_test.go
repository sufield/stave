package validate

import (
	"strings"
	"testing"
)

func TestNormalizeKind_AcceptsAliases(t *testing.T) {
	cases := map[string]string{
		"control":   "control",
		"controls":  "control",
		"obs":       "observation",
		"snapshots": "observation",
		"finding":   "finding",
		"findings":  "finding",
	}

	for input, want := range cases {
		got, err := normalizeKind(input)
		if err != nil {
			t.Fatalf("normalizeKind(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeKind(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestNormalizeKind_SuggestsClosestValue(t *testing.T) {
	_, err := normalizeKind("contrl")
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
	if !strings.Contains(err.Error(), `Did you mean "control"?`) {
		t.Fatalf("expected suggestion, got: %v", err)
	}
}
