package kernel

import (
	"encoding/json"
	"testing"
)

func TestParsePrincipalScope(t *testing.T) {
	tests := []struct {
		in      string
		want    PrincipalScope
		wantErr bool
	}{
		{in: "public", want: ScopePublic},
		{in: "authenticated", want: ScopeAuthenticated},
		{in: "cross_account", want: ScopeCrossAccount},
		{in: "account", want: ScopeAccount},
		{in: "n/a", want: ScopeNotApplicable},
		{in: "unknown", want: ScopeUnknown},
		{in: "", want: ScopeUnknown},
		{in: "  Public  ", want: ScopePublic},
		{in: "global", wantErr: true},
		{in: "global_authenticated", wantErr: true},
		{in: "private", wantErr: true},
		{in: "bad_value", wantErr: true},
	}

	for _, tt := range tests {
		got, err := ParsePrincipalScope(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("ParsePrincipalScope(%q) error = nil, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParsePrincipalScope(%q) error = %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParsePrincipalScope(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestPrincipalScopeJSON(t *testing.T) {
	var scope PrincipalScope
	if err := json.Unmarshal([]byte(`"public"`), &scope); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if scope != ScopePublic {
		t.Fatalf("scope = %v, want %v", scope, ScopePublic)
	}

	data, err := json.Marshal(ScopeAuthenticated)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}
	if string(data) != `"authenticated"` {
		t.Fatalf("json.Marshal = %s, want %q", data, `"authenticated"`)
	}
}

func TestPrincipalScopeIsValid(t *testing.T) {
	valid := []PrincipalScope{
		ScopeNotApplicable, ScopePublic, ScopeAuthenticated,
		ScopeCrossAccount, ScopeAccount,
	}
	for _, s := range valid {
		if !s.IsValid() {
			t.Errorf("expected %v to be valid", s)
		}
	}

	invalid := []PrincipalScope{ScopeUnknown, PrincipalScope(99)}
	for _, s := range invalid {
		if s.IsValid() {
			t.Errorf("expected %v to be invalid", s)
		}
	}
}

func TestPrincipalScopeString(t *testing.T) {
	tests := []struct {
		scope PrincipalScope
		want  string
	}{
		{ScopeUnknown, "unknown"},
		{ScopeNotApplicable, "n/a"},
		{ScopePublic, "public"},
		{ScopeAuthenticated, "authenticated"},
		{ScopeCrossAccount, "cross_account"},
		{ScopeAccount, "account"},
		{PrincipalScope(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.scope.String(); got != tt.want {
			t.Errorf("PrincipalScope(%d).String() = %q, want %q", tt.scope, got, tt.want)
		}
	}
}
