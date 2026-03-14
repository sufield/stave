package kernel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NetworkScope defines the network-level access boundary of a policy grant.
type NetworkScope int

const (
	NetworkScopeUnknown       NetworkScope = iota
	NetworkScopePublic                     // no network condition
	NetworkScopeOrgRestricted              // aws:PrincipalOrgID condition
	NetworkScopeIPRestricted               // aws:SourceIp condition
	NetworkScopeVPCRestricted              // aws:sourceVpce / aws:SourceVpc condition
)

// String returns the canonical wire-format label for the scope.
func (s NetworkScope) String() string {
	switch s {
	case NetworkScopePublic:
		return "public"
	case NetworkScopeOrgRestricted:
		return "org-restricted"
	case NetworkScopeIPRestricted:
		return "ip-restricted"
	case NetworkScopeVPCRestricted:
		return "vpc-restricted"
	default:
		return ""
	}
}

// Rank returns the restrictiveness rank of the scope.
// Higher rank means more restrictive.
func (s NetworkScope) Rank() int {
	switch s {
	case NetworkScopeVPCRestricted:
		return 3
	case NetworkScopeIPRestricted:
		return 2
	case NetworkScopeOrgRestricted:
		return 1
	default:
		return 0 // public or unknown
	}
}

// WeakerThan reports whether s is less restrictive than other.
func (s NetworkScope) WeakerThan(other NetworkScope) bool {
	return s.Rank() < other.Rank()
}

// ParseNetworkScope converts a string label into its typed NetworkScope.
// It is case-insensitive and handles leading/trailing whitespace.
func ParseNetworkScope(raw string) (NetworkScope, error) {
	norm := strings.TrimSpace(strings.ToLower(raw))
	switch norm {
	case "", "unknown":
		return NetworkScopeUnknown, nil
	case "public":
		return NetworkScopePublic, nil
	case "org-restricted":
		return NetworkScopeOrgRestricted, nil
	case "ip-restricted":
		return NetworkScopeIPRestricted, nil
	case "vpc-restricted":
		return NetworkScopeVPCRestricted, nil
	default:
		return NetworkScopeUnknown, fmt.Errorf("invalid network scope: %q", raw)
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (s NetworkScope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *NetworkScope) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	return s.assign(str)
}

// MarshalYAML implements the yaml.Marshaler interface.
func (s NetworkScope) MarshalYAML() (any, error) {
	return s.String(), nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *NetworkScope) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	return s.assign(str)
}

// assign is a private helper to update the enum value from a string.
func (s *NetworkScope) assign(raw string) error {
	parsed, err := ParseNetworkScope(raw)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
