package exempt

import (
	"testing"
)

func TestBugHunt_AddException_Deduplication(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	// Add an exception twice
	err1 := f.AddException(ExceptionEntry{
		ControlID:  "CTL.TEST.001",
		AssetID:    "asset-a",
		ExpiryDate: "2026-12-31",
		Reason:     "original reason",
	}, "2025-11-15T14:00:00Z")
	if err1 != nil {
		t.Fatalf("first AddException failed: %v", err1)
	}

	err2 := f.AddException(ExceptionEntry{
		ControlID:  "CTL.TEST.001",
		AssetID:    "asset-a",
		ExpiryDate: "2027-12-31",
		Reason:     "updated reason",
	}, "2025-11-15T14:00:00Z")
	if err2 != nil {
		t.Fatalf("second AddException failed: %v", err2)
	}

	if len(f.Exceptions) != 1 {
		t.Fatalf("expected 1 exception entry (updated in-place), got %d (duplicate appended)", len(f.Exceptions))
	}
	if f.Exceptions[0].ExpiryDate != "2027-12-31" || f.Exceptions[0].Reason != "updated reason" {
		t.Errorf("exception fields not updated correctly: %+v", f.Exceptions[0])
	}
}

func TestBugHunt_AddExemption_Deduplication(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	// Add an exemption twice
	err1 := f.AddExemption(ExemptionEntry{
		AssetPattern: "arn:aws:s3:::sandbox-*",
		Reason:       "original reason",
	})
	if err1 != nil {
		t.Fatalf("first AddExemption failed: %v", err1)
	}

	err2 := f.AddExemption(ExemptionEntry{
		AssetPattern: "arn:aws:s3:::sandbox-*",
		Reason:       "updated reason",
	})
	if err2 != nil {
		t.Fatalf("second AddExemption failed: %v", err2)
	}

	if len(f.Exemptions) != 1 {
		t.Fatalf("expected 1 exemption entry (updated in-place), got %d (duplicate appended)", len(f.Exemptions))
	}
	if f.Exemptions[0].Reason != "updated reason" {
		t.Errorf("exemption fields not updated correctly: %+v", f.Exemptions[0])
	}
}
