package compliance

import (
	"testing"

	s3policy "github.com/sufield/stave/internal/platform/providers/aws/s3/policy"
)

func TestParsePolicyStatements(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantCount int
		wantErr   bool // malformed (present-but-unparseable) policies fail loud
	}{
		{name: "empty string", json: "", wantCount: 0},
		{name: "invalid json", json: "{bad", wantErr: true}, // fail-loud: not "0 statements"
		{name: "no statement key", json: `{"Version":"2012-10-17"}`, wantCount: 0},
		{
			name:      "single statement as object",
			json:      `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Principal":"*"}}`,
			wantCount: 1,
		},
		{
			name: "array of statements",
			json: `{"Statement":[
				{"Effect":"Allow","Action":"s3:GetObject","Principal":"*"},
				{"Effect":"Deny","Action":"s3:DeleteObject","Principal":"*"}
			]}`,
			wantCount: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmts, err := ParsePolicyStatements(tc.json)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a parse error for malformed policy, got nil (would mask exposure)")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(stmts) != tc.wantCount {
				t.Errorf("got %d statements, want %d", len(stmts), tc.wantCount)
			}
		})
	}
}

func TestPolicyStatement_HasWildcardPrincipal(t *testing.T) {
	// Each case constructs a NormalizedPrincipal directly — the same
	// result the parse-time normalization would produce. The earlier
	// shape passed `any` values through a type-switch on every
	// HasWildcardPrincipal call; the typed-internals bridge moves
	// that decision to UnmarshalJSON, so the test now exercises the
	// downstream method against the post-normalization shape.
	tests := []struct {
		name      string
		principal s3policy.NormalizedPrincipal
		want      bool
	}{
		{
			name:      "bare wildcard string",
			principal: s3policy.NormalizedPrincipal{Wildcard: true},
			want:      true,
		},
		{
			name:      "specific AWS ARN",
			principal: s3policy.NormalizedPrincipal{AWSARNs: []string{"arn:aws:iam::123:root"}},
			want:      false,
		},
		{
			name:      "AWS-key wildcard",
			principal: s3policy.NormalizedPrincipal{Wildcard: true, AWSARNs: []string{"*"}},
			want:      true,
		},
		{
			name:      "AWS-key list with wildcard",
			principal: s3policy.NormalizedPrincipal{Wildcard: true, AWSARNs: []string{"*"}},
			want:      true,
		},
		{
			name:      "AWS-key specific only",
			principal: s3policy.NormalizedPrincipal{AWSARNs: []string{"arn:aws:iam::123:root"}},
			want:      false,
		},
		{
			name:      "empty principal",
			principal: s3policy.NormalizedPrincipal{},
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := PolicyStatement{Principal: tc.principal}
			if got := s.HasWildcardPrincipal(); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPolicyStatement_HasWildcardPrincipal_FromJSON pins the
// parse-boundary contract: JSON forms that previously round-tripped
// through compliance.parseOneStatement now flow through
// s3/policy.Parse via ParsePolicyStatements. Every legacy wire form
// for "wildcard principal" must still light up the predicate.
func TestPolicyStatement_HasWildcardPrincipal_FromJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want bool
	}{
		{
			name: "string wildcard",
			json: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`,
			want: true,
		},
		{
			name: "AWS-key wildcard string",
			json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`,
			want: true,
		},
		{
			name: "AWS-key wildcard list",
			json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:GetObject"}]}`,
			want: true,
		},
		{
			name: "specific ARN string",
			json: `{"Statement":[{"Effect":"Allow","Principal":"arn:aws:iam::123:root","Action":"s3:GetObject"}]}`,
			want: false,
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
			if got := stmts[0].HasWildcardPrincipal(); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyStatement_HasWildcardAction(t *testing.T) {
	tests := []struct {
		name    string
		actions []string
		want    bool
	}{
		{name: "s3 wildcard", actions: []string{"s3:*"}, want: true},
		{name: "full wildcard", actions: []string{"*"}, want: true},
		{name: "specific", actions: []string{"s3:GetObject"}, want: false},
		{name: "mixed with wildcard", actions: []string{"s3:GetObject", "s3:*"}, want: true},
		{name: "empty", actions: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := PolicyStatement{Action: tc.actions}
			if got := s.HasWildcardAction(); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyStatement_HasAction(t *testing.T) {
	s := PolicyStatement{Action: []string{"s3:GetObject", "s3:ListBucket"}}

	if !s.HasAction("s3:ListBucket") {
		t.Error("expected true for s3:ListBucket")
	}
	if !s.HasAction("S3:LISTBUCKET") {
		t.Error("expected case-insensitive match")
	}
	if s.HasAction("s3:DeleteObject") {
		t.Error("expected false for s3:DeleteObject")
	}
}
