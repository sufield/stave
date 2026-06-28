package iam

import "testing"

func TestBugHunt_IntersectAction_SpecificCases(t *testing.T) {
	// Test overlapping wildcards s3:* and s3:Get*
	act, ok := intersectAction("s3:*", "s3:Get*")
	if !ok {
		t.Fatalf("expected intersectAction(\"s3:*\", \"s3:Get*\") to succeed")
	}
	if act != "s3:Get*" {
		t.Errorf("got %q, want %q", act, "s3:Get*")
	}

	act2, ok2 := intersectAction("s3:Get*", "s3:*")
	if !ok2 {
		t.Fatalf("expected intersectAction(\"s3:Get*\", \"s3:*\") to succeed")
	}
	if act2 != "s3:Get*" {
		t.Errorf("got %q, want %q", act2, "s3:Get*")
	}

	// Test non-overlapping wildcards
	_, ok3 := intersectAction("s3:Get*", "ec2:*")
	if ok3 {
		t.Errorf("expected intersectAction(\"s3:Get*\", \"ec2:*\") to fail")
	}
}
