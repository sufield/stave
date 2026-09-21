package gate

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBaselineEntries_DomainMethods(t *testing.T) {
	entries := BaselineEntries{
		{ControlID: kernel.ControlID("CTL.A.001"), AssetID: asset.ID("asset-1")},
		{ControlID: kernel.ControlID("CTL.B.001"), AssetID: asset.ID("asset-2")},
	}

	if entries.Len() != 2 {
		t.Errorf("Len: got %d, want 2", entries.Len())
	}
	if !entries.ContainsControl("CTL.A.001") {
		t.Error("ContainsControl CTL.A.001: got false, want true")
	}
	if entries.ContainsControl("CTL.C.001") {
		t.Error("ContainsControl CTL.C.001: got true, want false")
	}
	if filtered := entries.ByControl("CTL.A.001"); filtered.Len() != 1 {
		t.Errorf("ByControl CTL.A.001: got %d, want 1", filtered.Len())
	}
}
