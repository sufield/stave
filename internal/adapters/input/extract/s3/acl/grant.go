package acl

import "strings"

const (
	permRead        = "READ"
	permWrite       = "WRITE"
	permReadACL     = "READ_ACP"
	permWriteACL    = "WRITE_ACP"
	permFullControl = "FULL_CONTROL"
)

// Grant represents a single ACL grant from adapters or fixtures.
type Grant struct {
	Grantee    string // URI or ID
	Permission string // READ, WRITE, READ_ACP, WRITE_ACP, FULL_CONTROL
	Type       string `json:"type,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// Grants is a collection helper for ACL grant slices.
type Grants []Grant

func (g Grant) normalizedGrantee() string {
	return strings.ToLower(strings.TrimSpace(g.Grantee))
}

func (g Grant) normalizedPermission() string {
	return strings.ToUpper(strings.TrimSpace(g.Permission))
}

// IsAllUsers reports whether the grant targets the global AllUsers principal.
func (g Grant) IsAllUsers() bool {
	return isAllUsersPrincipalToken(g.normalizedGrantee())
}

// IsAuthenticatedUsers reports whether the grant targets AuthenticatedUsers.
func (g Grant) IsAuthenticatedUsers() bool {
	return isAuthenticatedUsersPrincipalToken(g.normalizedGrantee())
}

// IsAuthenticatedOnly reports whether this grant is not world-public.
func (g Grant) IsAuthenticatedOnly() bool {
	return g.IsAuthenticatedUsers() && !g.IsAllUsers()
}

// IsPublic reports whether this grant applies to public or authenticated principals.
func (g Grant) IsPublic() bool {
	return g.IsAllUsers() || g.IsAuthenticatedUsers()
}

// HasFullControl reports whether the grant includes FULL_CONTROL.
func (g Grant) HasFullControl() bool {
	return g.normalizedPermission() == permFullControl
}

// Permissions returns ACL analysis bits for this grant.
func (g Grant) Permissions() Permission {
	return aclPermissionByString[g.normalizedPermission()]
}

// PublicGrantees returns public grantee identifiers in encounter order.
func (gs Grants) PublicGrantees() []string {
	if len(gs) == 0 {
		return nil
	}

	out := make([]string, 0, len(gs))
	for _, grant := range gs {
		if grant.IsPublic() {
			out = append(out, grant.Grantee)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
