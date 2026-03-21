package acl

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

// AWS canonical permission strings.
const (
	permRead        = "READ"
	permWrite       = "WRITE"
	permReadACP     = "READ_ACP"
	permWriteACP    = "WRITE_ACP"
	permFullControl = "FULL_CONTROL"
)

// Audience classifies the reach of an ACL grant.
type Audience int

const (
	// AudiencePrivate targets specific accounts or canonical users.
	AudiencePrivate Audience = iota
	// AudienceAllUsers targets the public internet (AllUsers group).
	AudienceAllUsers
	// AudienceAuthenticatedOnly targets any authenticated AWS user.
	AudienceAuthenticatedOnly
)

// String returns the text label for the audience.
func (a Audience) String() string {
	switch a {
	case AudienceAllUsers:
		return "all_users"
	case AudienceAuthenticatedOnly:
		return "authenticated"
	default:
		return "private"
	}
}

// MarshalText implements encoding.TextMarshaler for consistent output
// across all text-based serialization formats.
func (a Audience) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for consistent input
// across all text-based serialization formats.
func (a *Audience) UnmarshalText(text []byte) error {
	switch string(text) {
	case "all_users":
		*a = AudienceAllUsers
	case "authenticated":
		*a = AudienceAuthenticatedOnly
	case "private":
		*a = AudiencePrivate
	default:
		return fmt.Errorf("invalid audience %q", text)
	}
	return nil
}

// Grant represents a single entry in an S3 Access Control List.
type Grant struct {
	Grantee    string // URI for groups, or canonical ID for accounts
	Permission string // READ, WRITE, READ_ACP, WRITE_ACP, FULL_CONTROL
	Type       string `json:"type,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// Grants is a collection helper for ACL grant slices.
type Grants []Grant

// Audience determines who the grant applies to by inspecting the Grantee URI
// against the canonical AWS group identifiers.
//
// Uses suffix matching instead of Contains to avoid false positives:
// a principal like "arn:aws:iam::123:user/allusers-service" must not
// match as the public AllUsers group.
func (g Grant) Audience() Audience {
	switch {
	case matchesToken(g.Grantee, "allusers"):
		return AudienceAllUsers
	case matchesToken(g.Grantee, "authenticatedusers"):
		return AudienceAuthenticatedOnly
	default:
		return AudiencePrivate
	}
}

// matchesToken checks if a principal string matches a token via exact match,
// URI path suffix (".../AllUsers"), or AWS prefix ("AWS:AuthenticatedUsers").
func matchesToken(principal, token string) bool {
	v := strings.ToLower(strings.TrimSpace(principal))
	return v == token ||
		strings.HasSuffix(v, "/"+token) ||
		strings.HasSuffix(v, ":"+token)
}

// IsPublic reports whether this grant applies to public or authenticated principals.
func (g Grant) IsPublic() bool {
	return g.Audience() != AudiencePrivate
}

// HasFullControl reports whether the grant includes FULL_CONTROL.
func (g Grant) HasFullControl() bool {
	return strings.ToUpper(strings.TrimSpace(g.Permission)) == permFullControl
}

// Permissions maps the raw permission string to the risk permission bitmask.
func (g Grant) Permissions() risk.Permission {
	switch strings.ToUpper(strings.TrimSpace(g.Permission)) {
	case permRead:
		return risk.PermRead
	case permWrite:
		return risk.PermWrite
	case permReadACP:
		return risk.PermAdminRead
	case permWriteACP:
		return risk.PermAdminWrite
	case permFullControl:
		return risk.PermRead | risk.PermWrite | risk.PermAdminRead | risk.PermAdminWrite
	default:
		return 0
	}
}
