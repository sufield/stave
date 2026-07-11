package template

import "testing"

func TestVerify_AllMatch(t *testing.T) {
	expected := []Finding{
		{ControlID: "CTL.S3.001", ResourceID: "bucket-a"},
		{ControlID: "CTL.S3.002", ResourceID: "bucket-b"},
	}
	actual := []Finding{
		{ControlID: "CTL.S3.002", ResourceID: "bucket-b"},
		{ControlID: "CTL.S3.001", ResourceID: "bucket-a"},
	}

	result := Verify(expected, actual, nil)

	if !result.Pass() {
		t.Fatal("expected pass")
	}
	if result.MatchedCount != 2 {
		t.Fatalf("expected 2 matched, got %d", result.MatchedCount)
	}
}

func TestVerify_Missing(t *testing.T) {
	expected := []Finding{
		{ControlID: "CTL.S3.001", ResourceID: "bucket-a"},
		{ControlID: "CTL.S3.002", ResourceID: "bucket-b"},
	}
	actual := []Finding{
		{ControlID: "CTL.S3.001", ResourceID: "bucket-a"},
	}

	result := Verify(expected, actual, nil)

	if result.Pass() {
		t.Fatal("expected fail")
	}
	if len(result.Missing) != 1 {
		t.Fatalf("expected 1 missing, got %d", len(result.Missing))
	}
	if result.Missing[0].ControlID != "CTL.S3.002" {
		t.Fatalf("wrong missing control: %s", result.Missing[0].ControlID)
	}
}

func TestVerify_Unexpected(t *testing.T) {
	expected := []Finding{
		{ControlID: "CTL.S3.001", ResourceID: "bucket-a"},
	}
	actual := []Finding{
		{ControlID: "CTL.S3.001", ResourceID: "bucket-a"},
		{ControlID: "CTL.IAM.001", ResourceID: "role-x"},
	}

	result := Verify(expected, actual, nil)

	if result.Pass() {
		t.Fatal("expected fail")
	}
	if len(result.Unexpected) != 1 {
		t.Fatalf("expected 1 unexpected, got %d", len(result.Unexpected))
	}
}

func TestVerify_CustomMatchKeys(t *testing.T) {
	expected := []Finding{
		{ControlID: "CTL.S3.001", ResourceID: "bucket-a"},
	}
	actual := []Finding{
		{ControlID: "CTL.S3.001", ResourceID: "bucket-DIFFERENT"},
	}

	// Match on control_id only
	result := Verify(expected, actual, []string{"control_id"})
	if !result.Pass() {
		t.Fatal("expected pass with control_id-only matching")
	}
}
