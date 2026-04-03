package compliance

import "testing"

func TestParsePolicyStatements(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantCount int
	}{
		{name: "empty string", json: "", wantCount: 0},
		{name: "invalid json", json: "{bad", wantCount: 0},
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
	tests := []struct {
		name      string
		principal any
		want      bool
	}{
		{name: "string wildcard", principal: "*", want: true},
		{name: "string specific", principal: "arn:aws:iam::123:root", want: false},
		{name: "map with wildcard", principal: map[string]any{"AWS": "*"}, want: true},
		{name: "map with list wildcard", principal: map[string]any{"AWS": []any{"*"}}, want: true},
		{name: "map specific", principal: map[string]any{"AWS": "arn:aws:iam::123:root"}, want: false},
		{name: "nil", principal: nil, want: false},
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
