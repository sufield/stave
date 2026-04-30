package enginetest

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestNewVendor_NormalizesCaseAndWhitespace(t *testing.T) {
	t.Parallel()
	got, err := kernel.NewVendor("  AWS  ")
	if err != nil {
		t.Fatalf("NewVendor returned error: %v", err)
	}
	if got != kernel.Vendor("aws") {
		t.Fatalf("vendor = %q, want %q", got, "aws")
	}
}

func TestNewVendor_AcceptsAnyNonEmptyVendor(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"Kubernetes", "google", "internal", "azure"} {
		got, err := kernel.NewVendor(input)
		if err != nil {
			t.Fatalf("NewVendor(%q) returned error: %v", input, err)
		}
		if got != kernel.Vendor(strings.ToLower(input)) {
			t.Fatalf("vendor = %q, want %q", got, strings.ToLower(input))
		}
	}
}

func TestNewVendor_RejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := kernel.NewVendor("   "); err == nil {
		t.Fatal("expected error for empty vendor")
	}
}

func TestVendor_String_ZeroValue(t *testing.T) {
	t.Parallel()
	var v kernel.Vendor
	if got := v.String(); got != "unknown" {
		t.Fatalf("zero-value Vendor.String() = %q, want %q", got, "unknown")
	}
}
