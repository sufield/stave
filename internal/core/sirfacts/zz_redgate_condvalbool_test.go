package sirfacts

import (
	"testing"

	"github.com/sufield/stave/internal/core/sir"
)

// Test_RedGate_CondValBool is a RED-gate test for the bug at
// facts.go:853 (conditionFacts). has_condition is emitted for every
// (operator,key) pair, but has_condition_value is emitted via
// coerceStringList(keys[k]), which only accepts string or
// []any-of-strings and returns nil for any other type. A JSON-parsed
// IAM Condition value that is a boolean (e.g.
// {"Bool":{"aws:SecureTransport":false}}) is therefore silently
// dropped: the projector emits has_condition="Bool:aws:SecureTransport"
// but NO matching has_condition_value="Bool:aws:SecureTransport=false".
//
// The correct behavior is to emit the value fact so a closed-world
// query asking has_condition_value(p,"Bool:aws:SecureTransport=false")
// can match. This test asserts that value fact is present.
func Test_RedGate_CondValBool(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()

	doc := &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:     "arn:aws:iam::111122223333:role/transit",
				Type:   "aws_iam_role",
				Vendor: "aws",
				Properties: map[string]any{
					"identity": map[string]any{
						"policies": map[string]any{
							"attached_policies": []any{
								map[string]any{
									"statements": []any{
										map[string]any{
											"Effect":   "Allow",
											"Action":   "s3:*",
											"Resource": "*",
											"Condition": map[string]any{
												// JSON boolean parses to Go bool.
												"Bool": map[string]any{
													"aws:SecureTransport": false,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	facts := ExtractFacts(doc)

	// Sanity: the presence fact should be there (it does not go
	// through coerceStringList).
	const wantCond = "Bool:aws:SecureTransport"
	const wantVal = "Bool:aws:SecureTransport=false"

	condPresent := false
	valPresent := false
	for _, f := range facts {
		switch f.Predicate {
		case "has_condition":
			if f.Object == wantCond {
				condPresent = true
			}
		case "has_condition_value":
			if f.Object == wantVal {
				valPresent = true
			}
		}
	}
	if !condPresent {
		t.Fatalf("expected has_condition(%s) to be present; facts=%+v", wantCond, facts)
	}
	if !valPresent {
		t.Fatalf("boolean condition value silently dropped: missing has_condition_value(%s)", wantVal)
	}
}
