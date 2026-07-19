package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestStableFindingID_HashCollision(t *testing.T) {
	// First case: ctlID has a colon
	ctlID1 := kernel.ControlID("CTL.S3:PUBLIC")
	astID1 := asset.ID("001:my-bucket")

	// Second case: astID has a colon, but overall concatenated text is identical
	ctlID2 := kernel.ControlID("CTL.S3")
	astID2 := asset.ID("PUBLIC:001:my-bucket")

	id1 := StableFindingID(ctlID1, astID1)
	id2 := StableFindingID(ctlID2, astID2)

	if id1 == id2 {
		t.Errorf("Hash collision detected! Same ID %q produced for different inputs:\n  1. ctlID=%q, astID=%q\n  2. ctlID=%q, astID=%q", id1, ctlID1, astID1, ctlID2, astID2)
	}
}
