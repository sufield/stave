package exempt

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_ValidateWithCatalog_UnknownPrimaryControlID(t *testing.T) {
	t.Parallel()

	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{
				ControlID:  "CTL.UNKNOWN.ACK.001",
				AssetID:    "arn:a",
				Reason:     "test",
				Approver:   "alice",
				ExpiryDate: "2026-09-01",
			},
		},
		Exceptions: []ExceptionEntry{
			{
				ControlID: "CTL.UNKNOWN.EXC.001",
				AssetID:   "arn:b",
				Reason:    "testing exception",
			},
		},
	}

	knownIDs := map[kernel.ControlID]struct{}{
		"CTL.KNOWN.001": {},
	}

	errs := f.ValidateWithCatalog(knownIDs)

	hasAckError := false
	hasExcError := false
	for _, e := range errs {
		if strings.Contains(e, "CTL.UNKNOWN.ACK.001") && strings.Contains(e, "not found") {
			hasAckError = true
		}
		if strings.Contains(e, "CTL.UNKNOWN.EXC.001") && strings.Contains(e, "not found") {
			hasExcError = true
		}
	}

	if !hasAckError {
		t.Errorf("expected validation error for unknown acknowledgment control ID CTL.UNKNOWN.ACK.001, got: %v", errs)
	}
	if !hasExcError {
		t.Errorf("expected validation error for unknown exception control ID CTL.UNKNOWN.EXC.001, got: %v", errs)
	}
}
