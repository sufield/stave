package kernel

import "testing"

func TestObjectPrefix_Matches(t *testing.T) {
	tests := []struct {
		name   string
		scope  ObjectPrefix
		target ObjectPrefix
		want   bool
	}{
		{name: "wildcard matches anything", scope: "*", target: "invoices/", want: true},
		{name: "exact match with slash", scope: "invoices/", target: "invoices/", want: true},
		{name: "parent covers child", scope: "data/", target: "data/secrets/", want: true},
		{name: "mismatch", scope: "images/", target: "invoices/", want: false},
		{name: "empty scope never matches", scope: "", target: "anything", want: false},
		{name: "whitespace-only scope never matches", scope: "   ", target: "anything", want: false},
		{name: "scope without trailing slash", scope: "invoices", target: "invoices/2026", want: true},
		{name: "child does not cover parent", scope: "data/secrets/", target: "data/", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.scope.Matches(tt.target)
			if got != tt.want {
				t.Errorf("ObjectPrefix(%q).Matches(%q) = %v, want %v", tt.scope, tt.target, got, tt.want)
			}
		})
	}
}

func TestObjectPrefix_String(t *testing.T) {
	p := ObjectPrefix("invoices/")
	if p.String() != "invoices/" {
		t.Errorf("String() = %q, want %q", p.String(), "invoices/")
	}
}

func TestWildcardPrefix(t *testing.T) {
	if WildcardPrefix.String() != "*" {
		t.Errorf("WildcardPrefix = %q, want %q", WildcardPrefix, "*")
	}
	if !WildcardPrefix.Matches("anything") {
		t.Error("WildcardPrefix should match anything")
	}
}
