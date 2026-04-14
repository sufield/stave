package evaluation

import "testing"

func TestStableFindingID_Deterministic(t *testing.T) {
	id1 := StableFindingID("CTL.S3.PUBLIC.001", "arn:aws:s3:::my-bucket")
	id2 := StableFindingID("CTL.S3.PUBLIC.001", "arn:aws:s3:::my-bucket")
	if id1 != id2 {
		t.Errorf("same inputs should produce same ID: %q != %q", id1, id2)
	}
	if id1 == "" {
		t.Error("ID should not be empty")
	}
	if len(id1) < 10 {
		t.Errorf("ID too short: %q", id1)
	}
}

func TestStableFindingID_DifferentInputsDifferentID(t *testing.T) {
	id1 := StableFindingID("CTL.S3.PUBLIC.001", "arn:aws:s3:::bucket-a")
	id2 := StableFindingID("CTL.S3.PUBLIC.001", "arn:aws:s3:::bucket-b")
	if id1 == id2 {
		t.Error("different assets should produce different IDs")
	}
}

func TestStableFindingID_PrefixedWithSHA256(t *testing.T) {
	id := StableFindingID("CTL.A", "res1")
	if id[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix, got %q", id)
	}
}
