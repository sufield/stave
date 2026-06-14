package policy

import "testing"

// TestBugHunt_EmptyFederatedIsNotPublic proves that a bucket policy whose
// Principal is an EMPTY Federated string ({"Federated": ""}) is NOT public.
//
// NormalizeStringOrSlice("") returns []string{""} (a one-element slice
// holding the empty string), so populate() stores p.Federated = [""].
// Scope() (normalized.go) then classified the principal via
// `if len(p.Federated) > 0 { return ScopePublic }` — a length check that
// counts the empty-string placeholder as a real federated identity. The
// statement is therefore flagged ScopePublic, and Document.Assess() reports
// AllowsPublicRead=true for a policy that grants NO actual principal any
// access — a false positive.
//
// An empty Federated value names no identity. Per Scope's own contract
// ("Empty principal → Account, the safe default") and consistent with
// ConcreteAWSARNs (which already drops empty-string AWS entries), an
// all-empty Federated principal must classify as ScopeAccount, not public.
func TestBugHunt_EmptyFederatedIsNotPublic(t *testing.T) {
	t.Parallel()

	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"Federated": ""},
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	doc, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse returned error for valid policy: %v", err)
	}

	result := doc.Assess()

	if result.AllowsPublicRead {
		t.Errorf("expected AllowsPublicRead=false for a Principal of " +
			`{"Federated": ""} (empty string names no identity), got true; ` +
			"an empty Federated principal grants no public access and must " +
			"classify as ScopeAccount, not ScopePublic")
	}
}
