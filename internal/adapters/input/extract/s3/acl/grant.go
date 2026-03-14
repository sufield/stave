package acl

import (
	"strings"

	"github.com/samber/lo"
	"github.com/sufield/stave/internal/domain/kernel"
)

const (
	permRead        = "READ"
	permWrite       = "WRITE"
	permReadACL     = "READ_ACP"
	permWriteACL    = "WRITE_ACP"
	permFullControl = "FULL_CONTROL"
)

// GrantAudience classifies who a grant targets.
type GrantAudience int

const (
	// AudiencePrivate means the grant targets a specific account or user.
	AudiencePrivate GrantAudience = iota
	// AudienceAllUsers means the grant targets anonymous/public access.
	AudienceAllUsers
	// AudienceAuthenticatedOnly means the grant targets any authenticated AWS user.
	AudienceAuthenticatedOnly
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

// Audience classifies who this grant targets: AllUsers, AuthenticatedOnly, or Private.
func (g Grant) Audience() GrantAudience {
	switch {
	case g.IsAllUsers():
		return AudienceAllUsers
	case g.IsAuthenticatedUsers():
		return AudienceAuthenticatedOnly
	default:
		return AudiencePrivate
	}
}

// IsPublic reports whether this grant applies to public or authenticated principals.
func (g Grant) IsPublic() bool {
	return g.Audience() != AudiencePrivate
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
func (gs Grants) PublicGrantees() []kernel.GranteeID {
	return lo.FilterMap(gs, func(g Grant, _ int) (kernel.GranteeID, bool) {
		if g.IsPublic() {
			return kernel.GranteeID("uri:" + g.Grantee), true
		}
		return "", false
	})
}
