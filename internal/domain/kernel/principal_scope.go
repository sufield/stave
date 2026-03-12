package kernel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PrincipalScope defines the identity boundary of an access grant or exposure.
type PrincipalScope int

const (
	ScopeUnknown PrincipalScope = iota
	ScopeNotApplicable
	ScopePublic
	ScopeAuthenticated
	ScopeCrossAccount
	ScopeAccount
)

// String returns the canonical wire-format label for the scope.
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

// IsPublic reports whether the scope allows anonymous, unauthenticated access.
func (s PrincipalScope) IsPublic() bool {
	return s == ScopePublic
}

// IsValid reports whether the integer value represents a known scope.
func (s PrincipalScope) IsValid() bool {
	return s >= ScopeNotApplicable && s <= ScopeAccount
}

// ParsePrincipalScope converts a string label into its typed PrincipalScope.
// It is case-insensitive and handles leading/trailing whitespace.
func ParsePrincipalScope(raw string) (PrincipalScope, error) {
	norm := strings.TrimSpace(strings.ToLower(raw))
	switch norm {
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
		return ScopeUnknown, fmt.Errorf("invalid principal scope: %q", raw)
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (s PrincipalScope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *PrincipalScope) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	return s.assign(str)
}

// MarshalYAML implements the yaml.Marshaler interface.
func (s PrincipalScope) MarshalYAML() (any, error) {
	return s.String(), nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *PrincipalScope) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	return s.assign(str)
}

// assign is a private helper to update the enum value from a string.
func (s *PrincipalScope) assign(raw string) error {
	parsed, err := ParsePrincipalScope(raw)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
