package domain

import (
	"strings"
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

func TestParseVendor_AcceptsAnyNonEmptyVendor(t *testing.T) {
	for _, input := range []string{"Kubernetes", "google", "internal", "azure"} {
		got, err := kernel.ParseVendor(input)
		if err != nil {
			t.Fatalf("ParseVendor(%q) returned error: %v", input, err)
		}
		if got != kernel.Vendor(strings.ToLower(input)) {
			t.Fatalf("vendor = %q, want %q", got, strings.ToLower(input))
		}
	}
}

func TestParseVendor_RejectsEmpty(t *testing.T) {
	if _, err := kernel.ParseVendor("   "); err == nil {
		t.Fatal("expected error for empty vendor")
	}
}
