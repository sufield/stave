package predicate

import "testing"

func TestParamRef_String(t *testing.T) {
	tests := []struct {
		ref  ParamRef
		want string
	}{
		{"env", "env"},
		{"", ""},
		{"some.param", "some.param"},
	}
	for _, tt := range tests {
		if got := tt.ref.String(); got != tt.want {
			t.Errorf("ParamRef(%q).String() = %q, want %q", tt.ref, got, tt.want)
		}
	}
}

func TestParamRef_IsZero(t *testing.T) {
	tests := []struct {
		ref  ParamRef
		want bool
	}{
		{"", true},
		{"x", false},
	}
	for _, tt := range tests {
		if got := tt.ref.IsZero(); got != tt.want {
			t.Errorf("ParamRef(%q).IsZero() = %v, want %v", tt.ref, got, tt.want)
		}
	}
}
