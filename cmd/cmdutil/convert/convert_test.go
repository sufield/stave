package convert

import (
	"testing"
)

func TestToControlIDs_Empty(t *testing.T) {
	result, err := ToControlIDs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestToControlIDs_WithValues(t *testing.T) {
	result, err := ToControlIDs([]string{"CTL.S3.PUBLIC.001", " CTL.S3.ACL.002 ", "", "  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0] != "CTL.S3.PUBLIC.001" {
		t.Errorf("result[0] = %q", result[0])
	}
	if result[1] != "CTL.S3.ACL.002" {
		t.Errorf("result[1] = %q", result[1])
	}
}

func TestToControlIDs_InvalidFormat(t *testing.T) {
	_, err := ToControlIDs([]string{"CTL.S3.PUBLIC.001", "INVALID"})
	if err == nil {
		t.Fatal("expected error for invalid control ID format")
	}
}

func TestToAssetTypes_Empty(t *testing.T) {
	result := ToAssetTypes(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestToAssetTypes_WithValues(t *testing.T) {
	result := ToAssetTypes([]string{"aws:s3:bucket", "", "  "})
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	if result[0] != "aws:s3:bucket" {
		t.Errorf("result[0] = %q", result[0])
	}
}

func TestToControlIDs_AllEmpty(t *testing.T) {
	result, err := ToControlIDs([]string{"", "  ", " "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for all-empty input, got %v", result)
	}
}
