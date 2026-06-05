package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Bug 3: for a violation present in both scans, Remaining must carry the
// AFTER-scan state (current severity / escalation / dwell), not the stale
// before-scan finding.
func TestCompareVerificationFindings_RemainingUsesAfterState(t *testing.T) {
	key := struct {
		ctl kernel.ControlID
		ast asset.ID
	}{"CTL.S3.PUBLIC.001", "bucket-a"}

	before := []Finding{{
		ControlID:       key.ctl,
		AssetID:         key.ast,
		ControlSeverity: policy.SeverityMedium,
		Evidence:        Evidence{UnsafeDurationHours: 10},
	}}
	after := []Finding{{
		ControlID:       key.ctl,
		AssetID:         key.ast,
		ControlSeverity: policy.SeverityCritical, // escalated since the first scan
		Evidence:        Evidence{UnsafeDurationHours: 240},
	}}

	got := CompareVerificationFindings(before, after)

	if len(got.Remaining) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(got.Remaining))
	}
	r := got.Remaining[0]
	if r.ControlSeverity != policy.SeverityCritical {
		t.Errorf("Remaining severity = %q, want the AFTER value %q (stale before-state leaked)",
			r.ControlSeverity, policy.SeverityCritical)
	}
	if r.Evidence.UnsafeDurationHours != 240 {
		t.Errorf("Remaining dwell = %v, want the AFTER value 240", r.Evidence.UnsafeDurationHours)
	}
}
