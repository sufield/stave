package exempt

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoadSave_YAMLFieldCompatibility(t *testing.T) {
	// Verify that the YAML field names match what --acknowledgment-file expects
	// (rationale, acknowledged_by — not reason, approver).
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	f := &AcceptanceFile{SchemaVersion: "1"}
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "my rationale", Approver: "alice@co", ExpiryDate: "2026-09-01",
	}, "2025-11-15T14:00:00Z")
	_ = Save(path, f, "test", "2025-11-15T14:00:00Z")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	yaml := string(data)
	if !strings.Contains(yaml, "rationale: my rationale") {
		t.Errorf("YAML should use 'rationale' key, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "acknowledged_by: alice@co") {
		t.Errorf("YAML should use 'acknowledged_by' key, got:\n%s", yaml)
	}
	// Verify it does NOT use old field names.
	if strings.Contains(yaml, "reason: my rationale") {
		t.Error("YAML should NOT use 'reason' key — incompatible with --acknowledgment-file")
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
	// Build file with entries directly to test Upcoming() logic
	// (one expiring soon, one far future).
	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{
				ID: "CTL.A@arn:a", ControlID: "CTL.A", AssetID: "arn:a",
				Reason: "test", Approver: "alice", ExpiryDate: "2025-12-01",
				Status: "active",
			},
			{
				ID: "CTL.B@arn:b", ControlID: "CTL.B", AssetID: "arn:b",
				Reason: "test2", Approver: "bob", ExpiryDate: "2099-12-31",
				Status: "active",
			},
		},
	}

	// 30-day window from 2025-11-15 — CTL.A expires 2025-12-01 (within 30 days),
	// CTL.B far future (not within window).
	upcoming := f.Upcoming(30, time.Date(2025, 11, 15, 0, 0, 0, 0, time.UTC))
	if len(upcoming) != 1 {
		t.Errorf("upcoming = %d, want 1 (CTL.A within 30 days)", len(upcoming))
	}
}

func TestAddAcknowledgment_PastExpiryRejected(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	err := f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID:  "CTL.A",
		AssetID:    "arn:a",
		Reason:     "test",
		Approver:   "alice",
		ExpiryDate: "2020-01-01", // past date
	}, "2025-11-15T14:00:00Z")
	if err == nil {
		t.Error("expected error for past expiry date")
	}
}

func TestAddAcknowledgment_InvalidDateFormat(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	err := f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID:  "CTL.A",
		AssetID:    "arn:a",
		Reason:     "test",
		Approver:   "alice",
		ExpiryDate: "not-a-date",
	}, "2025-11-15T14:00:00Z")
	if err == nil {
		t.Error("expected error for invalid date format")
	}
}

func TestValidateWithCatalog_UnknownCompensating(t *testing.T) {
	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{
				ControlID:            "CTL.A",
				AssetID:              "arn:a",
				Reason:               "test",
				Approver:             "alice",
				ExpiryDate:           "2026-09-01",
				CompensatingControls: []string{"CTL.KNOWN.001", "CTL.FAKE.999"},
			},
		},
	}

	knownIDs := map[string]struct{}{"CTL.KNOWN.001": {}}
	errs := f.ValidateWithCatalog(knownIDs)

	found := false
	for _, e := range errs {
		if strings.Contains(e, "CTL.FAKE.999") && strings.Contains(e, "not found") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected error about CTL.FAKE.999 not in catalog, got: %v", errs)
	}
}

func TestValidateWithCatalog_AllKnown(t *testing.T) {
	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{
				ControlID:            "CTL.A",
				AssetID:              "arn:a",
				Reason:               "test",
				Approver:             "alice",
				ExpiryDate:           "2026-09-01",
				CompensatingControls: []string{"CTL.B"},
			},
		},
	}

	knownIDs := map[string]struct{}{"CTL.B": {}}
	errs := f.ValidateWithCatalog(knownIDs)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestHistory_IncludesAllEntries(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.A", AssetID: "arn:a", Reason: "active one", Approver: "alice", ExpiryDate: "2026-01-01",
	}, "2025-11-15T14:00:00Z")
	_ = f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID: "CTL.B", AssetID: "arn:b", Reason: "will revoke", Approver: "bob", ExpiryDate: "2026-01-01",
	}, "2025-11-15T14:00:00Z")
	_ = f.Remove("CTL.B@arn:b", "2025-11-15T15:00:00Z")

	history := f.History()
	if len(history) != 2 {
		t.Errorf("history = %d entries, want 2 (active + revoked)", len(history))
	}

	// Check revoked entry has 2 audit events.
	for _, h := range history {
		if h.ID == "CTL.B@arn:b" {
			if h.Status != "revoked" {
				t.Errorf("status = %q, want revoked", h.Status)
			}
			if len(h.AuditTrail) != 2 {
				t.Errorf("audit trail = %d, want 2", len(h.AuditTrail))
			}
		}
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

func TestAddAcknowledgment_EmptyTimestamp_NoPanic(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	err := f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID:  "CTL.A.001",
		AssetID:    "asset-1",
		Reason:     "test",
		ExpiryDate: "2027-01-01",
	}, "")
	if err == nil {
		t.Fatal("expected error for empty timestamp")
	}
}

func TestAddAcknowledgment_ShortTimestamp_NoPanic(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	err := f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID:  "CTL.A.001",
		AssetID:    "asset-1",
		Reason:     "test",
		ExpiryDate: "2027-01-01",
	}, "2026-01")
	if err == nil {
		t.Fatal("expected error for short timestamp")
	}
}

func TestAddAcknowledgment_ValidTimestamp(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}
	err := f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID:  "CTL.A.001",
		AssetID:    "asset-1",
		Reason:     "test",
		Approver:   "test-user",
		ExpiryDate: "2027-01-01",
	}, "2026-04-15T12:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Acknowledgments[0].AcknowledgedDate != "2026-04-15" {
		t.Errorf("date = %q, want 2026-04-15", f.Acknowledgments[0].AcknowledgedDate)
	}
}

func TestAddAcknowledgment_SameDayExpiryInTimezoneWithNegativeOffset(t *testing.T) {
	f := &AcceptanceFile{SchemaVersion: "1"}

	// June 22, 2026 at 20:18:10 in UTC-4 timezone (e.g. EDT) is June 23, 2026 at 00:18:10 UTC.
	// If the expiry is June 22, 2026, it is the same calendar day in the local timezone,
	// so it should not be considered "in the past" relative to the local date.
	err := f.AddAcknowledgment(AcknowledgmentEntry{
		ControlID:  "CTL.A",
		AssetID:    "arn:a",
		Reason:     "test",
		Approver:   "alice",
		ExpiryDate: "2026-06-22",
	}, "2026-06-22T20:18:10-04:00")
	if err != nil {
		t.Errorf("expected no error for same day expiry in local timezone, got: %v", err)
	}
}

func TestUpcoming_SameDayExpiry(t *testing.T) {
	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{
				ID: "CTL.A@arn:a", ControlID: "CTL.A", AssetID: "arn:a",
				Reason: "test", Approver: "alice", ExpiryDate: "2026-06-22",
				Status: "active",
			},
		},
	}

	// Checked on June 22 at 20:18:10 UTC-4 timezone (June 23 UTC).
	// An entry expiring on June 22 is expiring today (same local calendar day) and is not yet in the past
	// relative to the calendar day. It should be returned as upcoming (expiring within 30 days).
	upcoming := f.Upcoming(30, time.Date(2026, 6, 22, 20, 18, 10, 0, time.FixedZone("EDT", -4*3600)))
	if len(upcoming) != 1 {
		t.Errorf("expected 1 upcoming entry for same day expiry, got %d", len(upcoming))
	}
}

func TestDaysRemaining_SameDayInLocalTimezoneWithNegativeOffset(t *testing.T) {
	// Acknowledgment rule expires on 2026-06-23 (tomorrow relative to the local date of June 22).
	a := &AcknowledgmentEntry{
		ExpiryDate: "2026-06-23",
	}

	// Checked on June 22 at 20:18:10 in UTC-4 timezone (June 23 UTC).
	// In the local timezone, it is still June 22, so there is exactly 1 day remaining until June 23.
	now := time.Date(2026, 6, 22, 20, 18, 10, 0, time.FixedZone("EDT", -4*3600))
	days, ok := a.DaysRemaining(now)
	if !ok {
		t.Fatal("expected ok to be true")
	}
	if days != 1 {
		t.Errorf("expected 1 day remaining, got %d", days)
	}
}
