package baseline

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/reporting"
)

func TestEntriesToDomain(t *testing.T) {
	entries := []evaluation.BaselineEntry{
		{
			ControlID:   kernel.ControlID("CTL.A.001"),
			ControlName: "Test",
			AssetID:     "bucket-1",
			AssetType:   "s3_bucket",
		},
	}
	domain := entriesToDomain(entries)
	if len(domain) != 1 {
		t.Fatalf("len = %d", len(domain))
	}
	if domain[0].ControlID != "CTL.A.001" {
		t.Fatalf("ControlID = %q", domain[0].ControlID)
	}
	if domain[0].AssetID != "bucket-1" {
		t.Fatalf("AssetID = %q", domain[0].AssetID)
	}
}

func TestEntriesToDomain_Empty(t *testing.T) {
	domain := entriesToDomain(nil)
	if len(domain) != 0 {
		t.Fatalf("len = %d", len(domain))
	}
}

func TestDomainToEntries(t *testing.T) {
	findings := []reporting.BaselineFinding{
		{
			ControlID:   "CTL.A.001",
			ControlName: "Test",
			AssetID:     "bucket-1",
			AssetType:   "s3_bucket",
		},
	}
	entries := domainToEntries(findings)
	if len(entries) != 1 {
		t.Fatalf("len = %d", len(entries))
	}
	if entries[0].ControlID != "CTL.A.001" {
		t.Fatalf("ControlID = %v", entries[0].ControlID)
	}
}

func TestDomainToEntries_Empty(t *testing.T) {
	entries := domainToEntries(nil)
	if len(entries) != 0 {
		t.Fatalf("len = %d", len(entries))
	}
}

func TestRoundTrip(t *testing.T) {
	original := []evaluation.BaselineEntry{
		{
			ControlID:   "CTL.A.001",
			ControlName: "Test Control",
			AssetID:     "bucket-1",
			AssetType:   "s3_bucket",
		},
	}
	domain := entriesToDomain(original)
	roundTrip := domainToEntries(domain)
	if len(roundTrip) != 1 {
		t.Fatalf("len = %d", len(roundTrip))
	}
	if roundTrip[0].ControlID != original[0].ControlID {
		t.Fatalf("ControlID mismatch")
	}
	if roundTrip[0].AssetID != original[0].AssetID {
		t.Fatalf("AssetID mismatch")
	}
}
