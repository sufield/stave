package validate

import (
	"strings"
	"testing"
)

func TestNormalizeValidateKind_AcceptsAliases(t *testing.T) {
	cases := map[string]string{
		"control":   "control",
		"controls":  "control",
		"obs":       "observation",
		"snapshots": "observation",
		"finding":   "finding",
		"findings":  "finding",
	}

	for input, want := range cases {
		got, err := normalizeValidateKind(input)
		if err != nil {
			t.Fatalf("normalizeValidateKind(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeValidateKind(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestNormalizeValidateKind_SuggestsClosestValue(t *testing.T) {
	_, err := normalizeValidateKind("contrl")
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
	if !strings.Contains(err.Error(), `Did you mean "control"?`) {
		t.Fatalf("expected suggestion, got: %v", err)
	}
}
