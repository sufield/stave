package compliance

import "testing"

// TestBugHunt_IsDenyNonTLSCaseInsensitive proves that IsDenyNonTLS fails to
// recognize AWS-valid alternate casing of the condition operator and key.
//
// AWS condition operators (e.g. "Bool") and condition keys (e.g.
// "aws:SecureTransport") are case-insensitive in the IAM/S3 policy
// evaluation engine. A bucket policy Deny statement written as
//
//	{"Bool":{"aws:secureTransport":"false"}}   // alternate key casing
//	{"bool":{"aws:SecureTransport":"false"}}   // alternate operator casing
//
// genuinely enforces TLS. IsDenyNonTLS must therefore return true for any
// casing of the operator and key when the value is "false".
//
// The current implementation (policy_helper.go:148) does an exact-case
// NormalizedCondition.Lookup, so these statements return false, causing
// CONTROLS.004 to emit a false "no bucket policy statement denies non-TLS
// access" finding even though the policy does enforce TLS.
func TestBugHunt_IsDenyNonTLSCaseInsensitive(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "canonical casing (control)",
			json: `{
				"Statement": [{
					"Effect": "Deny",
					"Principal": "*",
					"Action": "s3:*",
					"Resource": "*",
					"Condition": {
						"Bool": { "aws:SecureTransport": "false" }
					}
				}]
			}`,
		},
		{
			name: "alternate key casing aws:secureTransport",
			json: `{
				"Statement": [{
					"Effect": "Deny",
					"Principal": "*",
					"Action": "s3:*",
					"Resource": "*",
					"Condition": {
						"Bool": { "aws:secureTransport": "false" }
					}
				}]
			}`,
		},
		{
			name: "alternate operator casing bool",
			json: `{
				"Statement": [{
					"Effect": "Deny",
					"Principal": "*",
					"Action": "s3:*",
					"Resource": "*",
					"Condition": {
						"bool": { "aws:SecureTransport": "false" }
					}
				}]
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmts, err := ParsePolicyStatements(tc.json)
			if err != nil {
				t.Fatalf("ParsePolicyStatements: %v", err)
			}
			if len(stmts) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(stmts))
			}
			// AWS treats the operator/key as case-insensitive, so every
			// casing of a Deny-when-not-TLS condition must be recognized
			// as enforcing TLS.
			if got := stmts[0].IsDenyNonTLS(); !got {
				t.Errorf("IsDenyNonTLS() = false, want true (AWS condition operator/key are case-insensitive; this policy does enforce TLS)")
			}
		})
	}
}
