package risk

import "testing"

// Test_RedGate_PublicAdminRead asserts the CORRECT behavior: a public
// statement that grants ONLY PermAdminRead (read of the resource's
// policy/ACL/config metadata, e.g. s3:GetBucketPolicy / GetBucketAcl
// exposed to everyone) is information disclosure and must produce at
// least one finding with a non-Safe score. The public-permission ladder
// has no PermAdminRead branch, so such a statement falls through to
// ScoreSafe (0) with zero findings — identical to a statement with no
// public access at all.
func Test_RedGate_PublicAdminRead(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Evaluate panicked: %v", r)
		}
	}()

	sc := StatementContext{
		Permissions: PermAdminRead,
		IsPublic:    true,
		IsAllow:     true,
	}

	got := sc.Evaluate()

	if got.Score == ScoreSafe {
		t.Fatalf("public read of resource config metadata (PermAdminRead) scored ScoreSafe(%d); information disclosure must score above Safe", int(ScoreSafe))
	}
	if len(got.Findings) == 0 {
		t.Fatalf("public read of resource config metadata (PermAdminRead) produced no findings; expected an information-disclosure finding")
	}
}
