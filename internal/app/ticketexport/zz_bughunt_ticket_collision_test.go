package ticketexport

import (
	"testing"
)

func TestBugHunt_StableTicketID_HashCollision(t *testing.T) {
	// A naive concatenation of controlID + "+" + assetID can cause different inputs
	// to produce identical ticket IDs, leading to collisions.
	id1 := StableTicketID("CTL+S3", "bucket")
	id2 := StableTicketID("CTL", "S3+bucket")

	if id1 == id2 {
		t.Fatalf("Hash collision: identical ticket IDs generated for different inputs: %q == %q", id1, id2)
	}
}
