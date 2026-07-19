package exempt

import (
	"testing"
)

func TestBugHunt_AddException_PastExpiryRejected(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	// Try to add an exception with an expiry date in the past (e.g. 2020-01-01)
	err := f.AddException(ExceptionEntry{
		ControlID:  "CTL.TEST.001",
		AssetID:    "asset-a",
		ExpiryDate: "2020-01-01",
		Reason:     "legacy system",
	}, "2025-11-15T14:00:00Z")

	if err == nil {
		t.Fatalf("expected AddException with past expiry date to return an error, but it succeeded")
	}
}
