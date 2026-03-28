package kernel

import "testing"

func TestOutputKind_IsValid(t *testing.T) {
	valid := []OutputKind{
		KindBaseline, KindBaselineCheck, KindCIDiff,
		KindEnforcement, KindGateCheck, KindObservationDelta,
		KindRemediationReport, KindSnapshotArchive, KindSnapshotPlan,
		KindSnapshotPrune, KindSnapshotQuality,
	}
	for _, k := range valid {
		if !k.IsValid() {
			t.Errorf("expected %q to be valid", k)
		}
	}
}

func TestOutputKind_IsValid_RejectsUnknown(t *testing.T) {
	invalid := []OutputKind{"", "invalid", "BASELINE", "evaluation"}
	for _, k := range invalid {
		if k.IsValid() {
			t.Errorf("expected %q to be invalid", k)
		}
	}
}

func TestOutputKind_String(t *testing.T) {
	if got := KindBaseline.String(); got != "baseline" {
		t.Errorf("String() = %q, want %q", got, "baseline")
	}
}
