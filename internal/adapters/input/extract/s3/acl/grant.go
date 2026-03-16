package acl

import "strings"

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

// Permissions maps the raw permission string to the domain bitmask.
func (g Grant) Permissions() Permission {
	switch strings.ToUpper(strings.TrimSpace(g.Permission)) {
	case permRead:
		return aclPermRead
	case permWrite:
		return aclPermWrite
	case permReadACP:
		return aclPermReadACP
	case permWriteACP:
		return aclPermWriteACP
	case permFullControl:
		return aclPermFullControl
	default:
		return 0
	}
}
