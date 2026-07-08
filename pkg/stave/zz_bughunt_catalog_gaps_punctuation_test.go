package stave

import (
	"testing"
)

func TestBugHunt_MatchControl_PunctuationFalseNegative(t *testing.T) {
	controls := []gapControlEntry{
		{
			id:      "CTL.S3.ENCRYPT.001",
			service: "s3",
			name:    "s3 encryption",
			desc:    "ensure s3 bucket has encryption",
		},
	}

	// Case 1: Without period - should match (overlap: ensure, bucket, encryption = 3)
	checkWithout := ChecklistItem{
		ID:          "CHK.S3.001",
		Service:     "s3",
		Description: "Ensure s3 bucket has encryption",
	}
	id1, status1 := matchControl(checkWithout, controls, false)
	if status1 != "covered" || id1 != "CTL.S3.ENCRYPT.001" {
		t.Fatalf("expected check without period to match: got status=%q, id=%q", status1, id1)
	}

	// Case 2: With period - under buggy code, "encryption." doesn't match "encryption",
	// so overlap is only 2 (ensure, bucket), failing to meet the threshold of 3.
	checkWith := ChecklistItem{
		ID:          "CHK.S3.002",
		Service:     "s3",
		Description: "Ensure s3 bucket has encryption.",
	}
	id2, status2 := matchControl(checkWith, controls, false)
	if status2 != "covered" || id2 != "CTL.S3.ENCRYPT.001" {
		t.Errorf("expected check with period to match: got status=%q, id=%q (punctuation caused false negative)", status2, id2)
	}
}
