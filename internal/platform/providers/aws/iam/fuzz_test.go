package iam

import "testing"

// FuzzParsePolicyDocument drives the full IAM resolution pipeline on arbitrary
// policy-document strings: ParsePolicyDocument -> Resolve -> AddResourcePolicy.
// None of these may panic on any input. Malformed JSON must surface as an
// error, never a crash; a successfully parsed document must flow through
// wildcard resolution and resource-policy indexing without panicking.
//
// Single-string signature so gosentry can drive it in grammar mode with
// fuzz/grammars/iam-policy-grammar.json; it also runs under native
// `go test -fuzz`.
func FuzzParsePolicyDocument(f *testing.F) {
	seeds := []string{
		// baseline
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::my-bucket/*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}`,
		`{}`,
		`{"Version":"2012-10-17","Statement":[]}`,
		// real Stave control-surface actions (catalog: passrole/tagsession/microvm/cognito/batch chains)
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::*:role/*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sts:AssumeRole","sts:TagSession"],"Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:CreateMicrovmShellAuthToken","Resource":"arn:aws:lambda:*:123456789012:microvm:*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cognito-idp:Admin*","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["batch:RegisterJobDefinition","batch:SubmitJob"],"Resource":"*"}]}`,
		// resource-based policy with a Principal (exercises AddResourcePolicy's principal extraction)
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`,
		// malformed / tricky — must error, never panic
		``,
		`null`,
		`{`,
		`[]`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":42,"Resource":{}}]}`,
		`{"Version":"2012-10-17","Statement":"not-an-array"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, policyDoc string) {
		doc, err := ParsePolicyDocument(policyDoc)
		if err != nil {
			return // malformed input is expected to error, not crash
		}
		// Parsed cleanly: the rest of the pipeline must also survive any input.
		_ = Resolve(ResolutionInput{
			PrincipalARN:     "arn:aws:iam::111122223333:role/fuzz",
			IdentityPolicies: []PolicyDocument{doc},
		})
		idx := NewResourceAccessIndex()
		_ = AddResourcePolicy(idx, "arn:aws:s3:::fuzz-bucket", policyDoc, "111122223333")
	})
}
