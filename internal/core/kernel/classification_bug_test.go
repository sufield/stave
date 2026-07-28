package kernel

import (
	"testing"
)

func TestControlID_Classify_TrailingKeyword(t *testing.T) {
	t.Parallel()

	pubID := ControlID("CTL.S3.PUBLIC")
	if got := pubID.Classify(); got != ClassPublicExposure {
		t.Errorf("CRITICAL BUG: Classify(\"CTL.S3.PUBLIC\") = %s, want %s; failed to match trailing segment keyword", got, ClassPublicExposure)
	}

	encID := ControlID("CTL.S3.ENCRYPT")
	if got := encID.Classify(); got != ClassEncryptionMissing {
		t.Errorf("CRITICAL BUG: Classify(\"CTL.S3.ENCRYPT\") = %s, want %s; failed to match trailing segment keyword", got, ClassEncryptionMissing)
	}
}
