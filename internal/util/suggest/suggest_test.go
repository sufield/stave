package suggest

import "testing"

func TestClosest_FindsNearestCandidate(t *testing.T) {
	candidates := []string{"--max-unsafe", "--controls", "--observations"}
	got := Closest("--max-gap", candidates)
	if got != "--max-unsafe" {
		t.Fatalf("Closest()=%q, want %q", got, "--max-unsafe")
	}
}

func TestClosest_IsCaseInsensitive(t *testing.T) {
	candidates := []string{"CONTROL", "OBSERVATION", "FINDING"}
	got := Closest("contrl", candidates)
	if got != "CONTROL" {
		t.Fatalf("Closest()=%q, want %q", got, "CONTROL")
	}
}

func TestClosest_ReturnsEmptyWhenNoReasonableMatch(t *testing.T) {
	candidates := []string{"--max-unsafe", "--controls", "--observations"}
	got := Closest("--zzz", candidates)
	if got != "" {
		t.Fatalf("Closest()=%q, want empty", got)
	}
}

// TestDistance_UTF8Runes pins that Distance counts user-visible
// characters, not bytes. The earlier byte-indexed implementation
// compared a single 4-byte emoji as 4 individual edits against a
// substring missing it, which made fuzzy matches over names with
// emoji or accented characters meaninglessly expensive.
func TestDistance_UTF8Runes(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"café", "café", 0},
		{"café", "cafe", 1},
		{"hi🚀", "hi!", 1},
		{"🔥🚀x", "🔥🚀y", 1},
		{"", "café", 4},
	}
	for _, tc := range cases {
		got := Distance(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("Distance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
