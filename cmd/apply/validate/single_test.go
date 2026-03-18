package validate

import (
	"strings"
	"testing"

	schemas "github.com/sufield/stave/internal/contracts/schema"
)

func TestNormalizeKind_AcceptsAliases(t *testing.T) {
	cases := map[string]schemas.Kind{
		"control":   schemas.KindControl,
		"controls":  schemas.KindControl,
		"obs":       schemas.KindObservation,
		"snapshots": schemas.KindObservation,
		"finding":   schemas.KindFinding,
		"findings":  schemas.KindFinding,
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
