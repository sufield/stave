package engine

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestPartitionMarkerFindings_RoutesByControlType confirms findings
// emitted by TypeMarker controls land in the markers slice and
// findings from any other type stay in the violations slice.
func TestPartitionMarkerFindings_RoutesByControlType(t *testing.T) {
	t.Parallel()
	controls := []policy.ControlDefinition{
		{ID: kernel.ControlID("CTL.A"), Type: policy.TypeUnsafeState},
		{ID: kernel.ControlID("CTL.MARKER"), Type: policy.TypeMarker},
	}
	findings := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.A"), AssetID: "asset-1"},
		{ControlID: kernel.ControlID("CTL.MARKER"), AssetID: "asset-2"},
		{ControlID: kernel.ControlID("CTL.A"), AssetID: "asset-3"},
	}

	violations, markers := partitionMarkerFindings(findings, controls)
	if len(violations) != 2 {
		t.Errorf("violations = %d, want 2", len(violations))
	}
	if len(markers) != 1 {
		t.Errorf("markers = %d, want 1", len(markers))
	}
	if len(markers) == 1 && markers[0].ControlID != "CTL.MARKER" {
		t.Errorf("marker ControlID = %q, want CTL.MARKER", markers[0].ControlID)
	}
}

// TestPartitionMarkerFindings_FastPathNoMarkers is the common case
// in catalogs without marker controls. The input slice is returned
// as-is (no per-finding lookup) and markers stays nil.
func TestPartitionMarkerFindings_FastPathNoMarkers(t *testing.T) {
	t.Parallel()
	controls := []policy.ControlDefinition{
		{ID: kernel.ControlID("CTL.A"), Type: policy.TypeUnsafeState},
	}
	findings := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.A"), AssetID: "asset-1"},
		{ControlID: kernel.ControlID("CTL.A"), AssetID: "asset-2"},
	}
	violations, markers := partitionMarkerFindings(findings, controls)
	if len(violations) != 2 {
		t.Errorf("violations = %d, want 2", len(violations))
	}
	if markers != nil {
		t.Errorf("markers should be nil on fast path, got %v", markers)
	}
}

// TestPartitionMarkerFindings_EmptyInput returns empty slices on
// no findings — defensive for early-exit paths.
func TestPartitionMarkerFindings_EmptyInput(t *testing.T) {
	t.Parallel()
	controls := []policy.ControlDefinition{{ID: "X", Type: policy.TypeMarker}}
	violations, markers := partitionMarkerFindings(nil, controls)
	if len(violations) != 0 {
		t.Errorf("violations = %d, want 0", len(violations))
	}
	if len(markers) != 0 {
		t.Errorf("markers = %d, want 0", len(markers))
	}
}
