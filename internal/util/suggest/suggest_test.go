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
