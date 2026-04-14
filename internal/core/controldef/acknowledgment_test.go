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
