package sirfacts

import (
	"testing"

	"github.com/sufield/stave/internal/core/sir"
)

// Test_RedGate_IamPolicyPath is a RED-gate test for the bug at
// facts.go:506 (iamPolicyFacts). The Evidence string is built as
// "assets[%d].policies.attached_policies[%d].statements[%d]", but
// the property is navigated via navMap(a.Properties, "identity",
// "policies"), so the real observation path is
// properties.identity.policies.attached_policies[...]. The evidence
// drops the "properties.identity." segment. After annotateProvenance
// runs stripIndexPrefix (cut at first "]."), the resulting
// Provenance.PropertyPath is
// "policies.attached_policies[0].statements[0].Action" instead of
// "properties.identity.policies.attached_policies[0].statements[0].Action".
//
// The documented contract (Provenance doc comment) is that
// property_path is "greppable directly against the raw observation
// JSON". This test asserts the correct, full path.
func Test_RedGate_IamPolicyPath(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()

	doc := &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:     "arn:aws:iam::111122223333:role/app",
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
											"Action":   "s3:GetObject",
											"Resource": "arn:aws:s3:::b",
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

	var gotPath string
	found := false
	for _, f := range facts {
		if f.Predicate == "has_action" && f.Object == "s3:GetObject" {
			if f.Provenance == nil {
				t.Fatalf("has_action fact missing Provenance: %+v", f)
			}
			gotPath = f.Provenance.PropertyPath
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no has_action(s3:GetObject) fact emitted; facts=%+v", facts)
	}

	const wantPath = "properties.identity.policies.attached_policies[0].statements[0].Action"
	if gotPath != wantPath {
		t.Fatalf("property_path does not resolve against raw observation JSON:\n got  %q\n want %q", gotPath, wantPath)
	}
}
