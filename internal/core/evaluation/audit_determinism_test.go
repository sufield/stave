package evaluation

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/sets"
)

// Bug 1: a requested framework with zero mapped controls must report 0%,
// not a false 100% that reads as full compliance.
func TestCalculateReadiness_ZeroMappedFrameworkIsNotHundredPercent(t *testing.T) {
	r := &ComplianceReport{}
	allControlIDs := []kernel.ControlID{"CTL.A"}
	controlCompliance := map[kernel.ControlID]map[policy.ComplianceFramework]string{
		"CTL.A": {"soc2": "CC6.1"},
	}
	// "gdpr" has no mapped controls in the catalog.
	r.CalculateReadiness([]string{"gdpr"}, allControlIDs, controlCompliance)

	if len(r.Summary.FrameworkReadiness) != 1 {
		t.Fatalf("requested framework must stay in the list, got %d entries", len(r.Summary.FrameworkReadiness))
	}
	fr := r.Summary.FrameworkReadiness[0]
	if fr.TotalControls != 0 {
		t.Errorf("TotalControls = %d, want 0", fr.TotalControls)
	}
	if fr.ReadinessPercent != 0 {
		t.Errorf("ReadinessPercent = %d, want 0 (zero-mapped framework must NOT report 100%%)", fr.ReadinessPercent)
	}
}

// Bug 5: computeSuperFix must pick the same winner and emit the same
// Frameworks ordering on every run, even when controls tie.
func TestComputeSuperFix_DeterministicAcrossRuns(t *testing.T) {
	failingIDs := sets.New[kernel.ControlID]("CTL.B", "CTL.A", "CTL.C")
	// All three controls cover exactly 2 frameworks → a tie. The winner
	// must be the smallest control ID (CTL.A), and Frameworks sorted.
	controlCompliance := map[kernel.ControlID]map[policy.ComplianceFramework]string{
		"CTL.A": {"soc2": "x", "iso27001": "y"},
		"CTL.B": {"nist": "x", "pci": "y"},
		"CTL.C": {"hipaa": "x", "fedramp": "y"},
	}
	frameworks := []string{"soc2", "iso27001", "nist", "pci", "hipaa", "fedramp"}

	first := computeSuperFix(failingIDs, controlCompliance, frameworks)
	if first == nil {
		t.Fatal("expected a SuperFix")
	}
	for i := range 20 {
		got := computeSuperFix(failingIDs, controlCompliance, frameworks)
		if got.ControlID != first.ControlID {
			t.Fatalf("non-deterministic winner: run %d gave %s, first gave %s", i, got.ControlID, first.ControlID)
		}
		if len(got.Frameworks) != len(first.Frameworks) {
			t.Fatalf("framework count drift: %v vs %v", got.Frameworks, first.Frameworks)
		}
		for j := range got.Frameworks {
			if got.Frameworks[j] != first.Frameworks[j] {
				t.Fatalf("framework order drift on run %d: %v vs %v", i, got.Frameworks, first.Frameworks)
			}
		}
	}
	if first.ControlID != "CTL.A" {
		t.Errorf("tie must resolve to smallest control ID; got %s, want CTL.A", first.ControlID)
	}
	// Frameworks must be sorted.
	if first.Frameworks[0] != "iso27001" || first.Frameworks[1] != "soc2" {
		t.Errorf("Frameworks not sorted: %v", first.Frameworks)
	}
}

// computeNearbyFrameworks must compute the readiness percent and gap
// EXACTLY, and include a framework sitting on the >= 80% boundary. The
// ordering tests don't touch these values, so a wrong pct/gap formula or
// an off-by-one threshold goes unnoticed.
func TestComputeNearbyFrameworks_PercentGapAndBoundary(t *testing.T) {
	// "fw80": 5 controls mapped, 1 failing → 4/5 = exactly 80% readiness,
	// gap 1. Must be reported (>= 80, not > 80).
	allControlIDs := []kernel.ControlID{"C1", "C2", "C3", "C4", "C5"}
	cc := map[kernel.ControlID]map[policy.ComplianceFramework]string{}
	for _, id := range allControlIDs {
		cc[id] = map[policy.ComplianceFramework]string{"fw80": "x"}
	}
	failingIDs := sets.New[kernel.ControlID]("C5") // 4 of 5 pass

	got := computeNearbyFrameworks(failingIDs, allControlIDs, cc, sets.New[string]())
	if len(got) != 1 {
		t.Fatalf("framework at exactly 80%% must be reported (>= 80), got %d entries: %+v", len(got), got)
	}
	if got[0].ReadinessPercent != 80 {
		t.Errorf("ReadinessPercent = %d, want exactly 80 (passing*100/total = 4*100/5)", got[0].ReadinessPercent)
	}
	if got[0].GapCount != 1 {
		t.Errorf("GapCount = %d, want 1 (total-passing = 5-4)", got[0].GapCount)
	}
}

// computeSuperFix must NOT select a failing control whose frameworks are
// all outside the requested set — its fws list is empty, so it covers
// zero requested citations and cannot be the "most impactful fix".
func TestComputeSuperFix_EmptyFrameworkListNotSelected(t *testing.T) {
	failingIDs := sets.New[kernel.ControlID]("CTL.X")
	cc := map[kernel.ControlID]map[policy.ComplianceFramework]string{
		"CTL.X": {"unrequested": "y"}, // maps only to a framework not asked for
	}
	// Requested frameworks do NOT include "unrequested".
	if sf := computeSuperFix(failingIDs, cc, []string{"wanted"}); sf != nil {
		t.Fatalf("a control covering zero requested frameworks must not be a SuperFix, got %+v", sf)
	}
}

// Bug 6: computeNearbyFrameworks must return a list sorted by framework
// name, stable across runs.
func TestComputeNearbyFrameworks_SortedDeterministic(t *testing.T) {
	// No failing controls → every framework is 100% ready (>= 80%).
	failingIDs := sets.New[kernel.ControlID]()
	allControlIDs := []kernel.ControlID{"CTL.A", "CTL.B", "CTL.C"}
	controlCompliance := map[kernel.ControlID]map[policy.ComplianceFramework]string{
		"CTL.A": {"zeta": "x"},
		"CTL.B": {"alpha": "x"},
		"CTL.C": {"mu": "x"},
	}
	requested := sets.New[string]() // none requested → all are "nearby"

	first := computeNearbyFrameworks(failingIDs, allControlIDs, controlCompliance, requested)
	want := []string{"alpha", "mu", "zeta"}
	if len(first) != len(want) {
		t.Fatalf("got %d nearby, want %d", len(first), len(want))
	}
	for i := range want {
		if first[i].Framework != want[i] {
			t.Fatalf("nearby not sorted: got %q at %d, want %q", first[i].Framework, i, want[i])
		}
	}
	// Stable across runs.
	for i := range 20 {
		got := computeNearbyFrameworks(failingIDs, allControlIDs, controlCompliance, requested)
		for j := range got {
			if got[j].Framework != first[j].Framework {
				t.Fatalf("non-deterministic nearby order on run %d: %q vs %q", i, got[j].Framework, first[j].Framework)
			}
		}
	}
}
