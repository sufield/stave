package controldef

import (
	"testing"
	"time"
)

func TestAcknowledgmentRule_NotExpired(t *testing.T) {
	r := AcknowledgmentRule{ExpiryDate: "2026-12-31"}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if r.IsExpired(now) {
		t.Error("should not be expired")
	}
}

func TestAcknowledgmentRule_Expired(t *testing.T) {
	r := AcknowledgmentRule{ExpiryDate: "2025-01-01"}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !r.IsExpired(now) {
		t.Error("should be expired")
	}
}

func TestAcknowledgmentRule_NoExpiry(t *testing.T) {
	r := AcknowledgmentRule{ExpiryDate: ""}
	now := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	if r.IsExpired(now) {
		t.Error("empty expiry should never expire")
	}
}

func TestAcknowledgmentConfig_FindRule(t *testing.T) {
	cfg := NewAcknowledgmentConfig([]AcknowledgmentRule{
		{ControlID: "CTL.A", AssetID: "res1", Rationale: "accepted"},
	})
	r := cfg.FindRule("CTL.A", "res1")
	if r == nil {
		t.Fatal("expected to find rule")
	}
	if r.Rationale != "accepted" {
		t.Errorf("Rationale = %q", r.Rationale)
	}
}

func TestAcknowledgmentConfig_FindRule_NoMatch(t *testing.T) {
	cfg := NewAcknowledgmentConfig([]AcknowledgmentRule{
		{ControlID: "CTL.A", AssetID: "res1"},
	})
	r := cfg.FindRule("CTL.B", "res1")
	if r != nil {
		t.Error("expected nil for non-matching control")
	}
}

func TestAcknowledgmentConfig_Nil(t *testing.T) {
	var cfg *AcknowledgmentConfig
	r := cfg.FindRule("CTL.A", "res1")
	if r != nil {
		t.Error("expected nil for nil config")
	}
}

func TestAcknowledgmentRule_SameDayExpiryInTimezoneWithNegativeOffset(t *testing.T) {
	// Acknowledgment rule expires on 2026-06-22.
	r := AcknowledgmentRule{ExpiryDate: "2026-06-22"}

	// Checked on June 22 at 20:18:10 in UTC-4 timezone (June 23 UTC).
	// It is still June 22 in the local timezone, so the acknowledgment remains valid
	// for the entire day. It should NOT be considered expired.
	now := time.Date(2026, 6, 22, 20, 18, 10, 0, time.FixedZone("EDT", -4*3600))
	if r.IsExpired(now) {
		t.Error("should not be expired on the same calendar day in local timezone")
	}
}
