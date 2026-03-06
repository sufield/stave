package kernel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PrincipalScope defines who can exploit an exposure.
type PrincipalScope int

const (
	ScopeUnknown PrincipalScope = iota
	ScopeNotApplicable
	ScopePublic
	ScopeAuthenticated
	ScopeCrossAccount
	ScopeAccount
)

// String returns the canonical wire-format label.
func (s PrincipalScope) String() string {
	switch s {
	case ScopeNotApplicable:
		return "n/a"
	case ScopePublic:
		return "public"
	case ScopeAuthenticated:
		return "authenticated"
	case ScopeCrossAccount:
		return "cross_account"
	case ScopeAccount:
		return "account"
	default:
		return "unknown"
	}
}

// IsPublic reports whether the scope is globally public.
func (s PrincipalScope) IsPublic() bool {
	return s == ScopePublic
}

// ParsePrincipalScope converts a canonical wire label to PrincipalScope.
func ParsePrincipalScope(raw string) (PrincipalScope, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "unknown", "":
		return ScopeUnknown, nil
	case "n/a":
		return ScopeNotApplicable, nil
	case "public":
		return ScopePublic, nil
	case "authenticated":
		return ScopeAuthenticated, nil
	case "cross_account":
		return ScopeCrossAccount, nil
	case "account":
		return ScopeAccount, nil
	default:
		return ScopeUnknown, fmt.Errorf("unknown principal scope %q", raw)
	}
}

// MarshalJSON writes the canonical string label.
func (s PrincipalScope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON reads a scope string and validates it.
func (s *PrincipalScope) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed, err := ParsePrincipalScope(raw)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// MarshalYAML writes the canonical string label.
func (s PrincipalScope) MarshalYAML() (any, error) {
	return s.String(), nil
}

// UnmarshalYAML reads a scope string and validates it.
func (s *PrincipalScope) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	parsed, err := ParsePrincipalScope(raw)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
