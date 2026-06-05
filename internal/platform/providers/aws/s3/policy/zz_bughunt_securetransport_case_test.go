package policy

import "testing"

// TestBugHunt_SecureTransportCaseInsensitive proves that a valid
// TLS-enforcement bucket policy written with non-canonical casing for the
// condition operator and key is NOT detected by EnforcesHTTPS.
//
// AWS treats IAM condition operators ("Bool") and condition keys
// ("aws:SecureTransport") as case-insensitive. A policy author may legally
// write the same deny as {"bool":{"aws:securetransport":"false"}} and AWS
// enforces it identically — HTTPS is required.
//
// hasSecureTransportFalse (conditions.go:114) looks the value up via
// NormalizedCondition.Lookup with the exact-case keys condBool="Bool" and
// condSecureTransport="aws:SecureTransport". NormalizedCondition stores the
// author's original case and Lookup is exact-case, so the lowercase variant
// is missed. Statement.EnforcesHTTPS delegates here, so Document.Assess()
// reports EnforcesHTTPS=false for a bucket that DOES enforce HTTPS — a false
// negative.
//
// Correct behavior: the lookup is case-insensitive on operator and key, so
// this policy is recognized as a SecureTransport=false deny and
// EnforcesHTTPS returns true.
func TestBugHunt_SecureTransportCaseInsensitive(t *testing.T) {
	t.Parallel()

	// Same deny as the canonical TLS-enforcement policy, but with the
	// operator and key in non-canonical (lowercase) casing — still valid
	// per AWS's case-insensitive condition matching.
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"bool": {
					"aws:securetransport": "false"
				}
			}
		}]
	}`

	doc, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse returned error for valid policy: %v", err)
	}

	result := doc.Assess()

	if !result.EnforcesHTTPS {
		t.Errorf("expected EnforcesHTTPS=true for a Deny with case-insensitive "+
			"Bool/aws:SecureTransport=false condition ({\"bool\":{\"aws:securetransport\":\"false\"}}), got false; "+
			"AWS matches condition operators and keys case-insensitively, so this policy DOES enforce HTTPS")
	}
}
