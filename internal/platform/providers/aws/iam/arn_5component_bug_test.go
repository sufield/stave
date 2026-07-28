package iam

import (
	"testing"
)

func TestParseARN_FiveComponentARN_ExtractsAccountID(t *testing.T) {
	t.Parallel()

	arn := "arn:aws:iam::123456789012"
	got := ParseARN(arn)
	if got.AccountID != "123456789012" {
		t.Errorf("CRITICAL BUG: ParseARN(%q).AccountID = %q, want %q", arn, got.AccountID, "123456789012")
	}
}
