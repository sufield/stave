package exempt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAddAcknowledgment_RequiredFields(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	// Missing reason.
	err := f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Approver: "alice", ExpiryDate: "2026-01-01",
	}, "2025-11-15T14:00:00Z")
	if err == nil {
		t.Error("expected error for missing reason")
	}

	// Missing approver.
	err = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "test", ExpiryDate: "2026-01-01",
	}, "2025-11-15T14:00:00Z")
	if err == nil {
		t.Error("expected error for missing approver")
	}

	// Missing expiry.
	err = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "test", Approver: "alice",
	}, "2025-11-15T14:00:00Z")
	if err == nil {
		t.Error("expected error for missing expiry")
	}

	// All required fields present.
	err = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "test", Approver: "alice", ExpiryDate: "2026-09-01",
	}, "2025-11-15T14:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.Acknowledgments) != 1 {
		t.Fatalf("expected 1 acknowledgment, got %d", len(f.Acknowledgments))
	}
	if f.Acknowledgments[0].Status != "active" {
		t.Errorf("status = %q, want active", f.Acknowledgments[0].Status)
	}
	if f.Acknowledgments[0].ID != "CTL.A@arn:a" {
		t.Errorf("id = %q, want CTL.A@arn:a", f.Acknowledgments[0].ID)
	}
	if len(f.Acknowledgments[0].AuditTrail) != 1 {
		t.Errorf("audit trail = %d, want 1", len(f.Acknowledgments[0].AuditTrail))
	}
}

func TestRemove_MarksRevoked(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "test", Approver: "alice", ExpiryDate: "2026-09-01",
	}, "2025-11-15T14:00:00Z")

	err := f.Remove("CTL.A@arn:a", "2025-11-15T15:00:00Z")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if f.Acknowledgments[0].Status != "revoked" {
		t.Errorf("status = %q, want revoked", f.Acknowledgments[0].Status)
	}
	if len(f.Acknowledgments[0].AuditTrail) != 2 {
		t.Errorf("audit trail = %d, want 2 (created + revoked)", len(f.Acknowledgments[0].AuditTrail))
	}
}

func TestRemove_NotFound(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	err := f.Remove("nonexistent", "2025-11-15T15:00:00Z")
	if err == nil {
		t.Error("expected error for missing ID")
	}
}

func TestValidate(t *testing.T) {
	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{ControlID: "", AssetID: "arn:a", Reason: "test", Approver: "alice"},
		},
	}
	errs := f.Validate()
	if len(errs) == 0 {
		t.Error("expected validation errors for missing control_id")
	}
}

func TestValidate_BadDate(t *testing.T) {
	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{ControlID: "CTL.A", AssetID: "arn:a", Reason: "x", Approver: "a", ExpiryDate: "not-a-date"},
		},
	}
	errs := f.Validate()
	found := false
	for _, e := range errs {
		if e != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected date validation error")
	}
}

func TestLoadSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acceptances.yaml")

	f := &AcceptanceFile{SchemaVersion: "1"}
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "test", Approver: "alice", ExpiryDate: "2026-09-01",
	}, "2025-11-15T14:00:00Z")
	_ = f.AddException(ExceptionEntry{ControlID: "CTL.B", AssetID: "arn:b", Reason: "migration"})
	_ = f.AddExemption(ExemptionEntry{AssetPattern: "arn:aws:s3:::sandbox-*", Reason: "sandbox"})

	if err := Save(path, f, "test", "2025-11-15T14:00:00Z"); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Acknowledgments) != 1 {
		t.Errorf("acks = %d, want 1", len(loaded.Acknowledgments))
	}
	if len(loaded.Exceptions) != 1 {
		t.Errorf("exceptions = %d, want 1", len(loaded.Exceptions))
	}
	if len(loaded.Exemptions) != 1 {
		t.Errorf("exemptions = %d, want 1", len(loaded.Exemptions))
	}
}

func TestLoad_MissingFile(t *testing.T) {
	f, err := Load("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("missing file should return empty file, got error: %v", err)
	}
	if f.SchemaVersion != "1" {
		t.Errorf("schema = %q, want 1", f.SchemaVersion)
	}
}

func TestUpcoming(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "test", Approver: "alice",
		ExpiryDate: "2020-01-01", // already expired
	}, "2025-11-15T14:00:00Z")
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.B", AssetID: "arn:b", Reason: "test2", Approver: "bob",
		ExpiryDate: "2099-12-31", // far future
	}, "2025-11-15T14:00:00Z")

	// 30-day window — expired entry should show (it's before cutoff),
	// far future entry should not.
	upcoming := f.Upcoming(30, time.Date(2025, 11, 15, 0, 0, 0, 0, time.UTC))
	if len(upcoming) != 1 {
		t.Errorf("upcoming = %d, want 1 (the expired one is before cutoff)", len(upcoming))
	}
}

func TestActiveCount(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "x", Approver: "a", ExpiryDate: "2026-01-01",
	}, "2025-11-15T14:00:00Z")
	_ = f.Remove("CTL.A@arn:a", "2025-11-15T15:00:00Z") // revoke it
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.B", AssetID: "arn:b", Reason: "x", Approver: "a", ExpiryDate: "2026-01-01",
	}, "2025-11-15T14:00:00Z")

	acks, _, _ := f.ActiveCount()
	if acks != 1 {
		t.Errorf("active acks = %d, want 1 (CTL.A revoked)", acks)
	}

	_ = os.Remove("") // satisfy unused import
}
