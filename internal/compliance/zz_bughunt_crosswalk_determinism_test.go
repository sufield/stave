package compliance

import (
	"testing"
	"time"
)

func TestBugHunt_ResolveControlCrosswalk_Determinism(t *testing.T) {
	// Two crosswalk entries with same framework and control_id, but different rationales.
	// In the original code, the sorting function lacks a tie-breaker on Rationale,
	// leading to unstable sorting.
	raw := []byte(`
version: control_crosswalk.v1
checks:
  SC.BUILDINFO.PRESENT:
    - framework: soc2
      control_id: CC7.1
      rationale: rationale Z
    - framework: soc2
      control_id: CC7.1
      rationale: rationale A
`)

	res, err := ResolveControlCrosswalk(raw, []string{"soc2"}, []string{"SC.BUILDINFO.PRESENT"}, time.Now().UTC())
	if err != nil {
		t.Fatalf("ResolveControlCrosswalk failed: %v", err)
	}

	refs := res.ByCheck["SC.BUILDINFO.PRESENT"]
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}

	// We expect they are sorted alphabetically by Rationale: "rationale A" then "rationale Z"
	if refs[0].Rationale != "rationale A" {
		t.Errorf("refs[0].Rationale = %q, want rationale A", refs[0].Rationale)
	}
	if refs[1].Rationale != "rationale Z" {
		t.Errorf("refs[1].Rationale = %q, want rationale Z", refs[1].Rationale)
	}
}
