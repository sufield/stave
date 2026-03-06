package domain

import (
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"
)

func TestParseVendor_NormalizesCaseAndWhitespace(t *testing.T) {
	got, err := kernel.ParseVendor("  AWS  ")
	if err != nil {
		t.Fatalf("ParseVendor returned error: %v", err)
	}
	if got != kernel.VendorAWS {
		t.Fatalf("vendor = %q, want %q", got, kernel.VendorAWS)
	}
}

func TestParseVendor_RejectsNonAWSVendors(t *testing.T) {
	if _, err := kernel.ParseVendor("Kubernetes"); err == nil {
		t.Fatal("expected error for unsupported vendor")
	}
}

func TestParseVendor_RejectsEmpty(t *testing.T) {
	if _, err := kernel.ParseVendor("   "); err == nil {
		t.Fatal("expected error for empty vendor")
	}
}
