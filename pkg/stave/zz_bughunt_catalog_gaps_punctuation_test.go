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

	// Case 1: Without period - should match as candidate (fuzzy: overlap >= 3)
	checkWithout := ChecklistItem{
		ID:          "CHK.S3.001",
		Service:     "s3",
		Description: "Ensure s3 bucket has encryption",
	}
	id1, status1 := matchControl(checkWithout, controls, false)
	if status1 != "candidate" || id1 != "CTL.S3.ENCRYPT.001" {
		t.Fatalf("expected fuzzy match as candidate: got status=%q, id=%q", status1, id1)
	}

	// Case 2: With period - punctuation must not prevent fuzzy match
	checkWith := ChecklistItem{
		ID:          "CHK.S3.002",
		Service:     "s3",
		Description: "Ensure s3 bucket has encryption.",
	}
	id2, status2 := matchControl(checkWith, controls, false)
	if status2 != "candidate" || id2 != "CTL.S3.ENCRYPT.001" {
		t.Errorf("expected fuzzy match as candidate with period: got status=%q, id=%q", status2, id2)
	}
}
