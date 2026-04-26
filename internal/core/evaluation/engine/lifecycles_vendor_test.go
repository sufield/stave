package engine

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestVendorIndex_UnmatchedVendorReturnsEmpty verifies that a vendor
// with no matching controls and no universal controls gets an empty
// list back, not the full catalog. Wrong-vendor assets must not
// evaluate against every control.
func TestVendorIndex_UnmatchedVendorReturnsEmpty(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.AWS.A", ScopeTags: []kernel.ScopeTag{"aws"}},
		{ID: "CTL.AWS.B", ScopeTags: []kernel.ScopeTag{"aws"}},
	}
	idx := buildControlVendorIndex(controls)

	got := idx.controlsFor(kernel.Vendor("azure"), controls)
	if len(got) != 0 {
		t.Errorf("controlsFor(azure) = %d controls, want 0 (catalog has only AWS-tagged controls)", len(got))
	}
}

// TestVendorIndex_UniversalControlsAlwaysApply verifies that a
// universal control (no scope tags) reaches every vendor.
func TestVendorIndex_UniversalControlsAlwaysApply(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.AWS.A", ScopeTags: []kernel.ScopeTag{"aws"}},
		{ID: "CTL.UNIVERSAL", ScopeTags: nil},
	}
	idx := buildControlVendorIndex(controls)

	got := idx.controlsFor(kernel.Vendor("azure"), controls)
	if len(got) != 1 || got[0].ID != "CTL.UNIVERSAL" {
		t.Errorf("controlsFor(azure) = %v, want [CTL.UNIVERSAL]", got)
	}
}

// TestVendorIndex_MatchingVendorReturnsScopedControls confirms the
// happy path still works.
func TestVendorIndex_MatchingVendorReturnsScopedControls(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.AWS.A", ScopeTags: []kernel.ScopeTag{"aws"}},
		{ID: "CTL.GCP.A", ScopeTags: []kernel.ScopeTag{"gcp"}},
	}
	idx := buildControlVendorIndex(controls)

	got := idx.controlsFor(kernel.Vendor("aws"), controls)
	if len(got) != 1 || got[0].ID != "CTL.AWS.A" {
		t.Errorf("controlsFor(aws) = %v, want [CTL.AWS.A]", got)
	}
}
