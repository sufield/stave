package acl

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// S3 Canonical Group URIs.
// These are opaque identifiers defined by AWS, NOT HTTP endpoints — Stave never fetches them.
// See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee
const (
	GroupAllUsers           = "http://acs.amazonaws.com/groups/global/AllUsers"
	GroupAuthenticatedUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// List represents an S3 Access Control List as an immutable collection of grants.
type List struct {
	grants []Grant
}

// New creates a new ACL List with a defensive copy of the provided grants.
func New(grants []Grant) List {
	return List{grants: slices.Clone(grants)}
}

// Assessment contains the result of evaluating an ACL for security posture.
type Assessment struct {
	Permissions    map[Audience]risk.Permission `json:"permissions"`
	PublicGrantees []kernel.GranteeID           `json:"public_grantees,omitempty"`
}

// Assess evaluates the ACL grants and returns a summary of effective permissions.
func (l List) Assess() Assessment {
	perms := make(map[Audience]risk.Permission, 2)
	var publicIDs []kernel.GranteeID

	for _, g := range l.grants {
		aud := g.Audience()
		if aud == AudiencePrivate {
			continue
		}
		perms[aud] |= g.Permissions()
		if aud == AudienceAllUsers {
			publicIDs = append(publicIDs, kernel.GranteeID(g.Grantee))
		}
	}

	return Assessment{
		Permissions:    perms,
		PublicGrantees: publicIDs,
	}
}

// Assess is a package-level convenience for one-off grant evaluation.
func Assess(grants []Grant) Assessment {
	return New(grants).Assess()
}

// classifyGrantee determines the audience of a grantee URI by suffix matching.
// This is the single source of truth for public grantee detection — both
// IsPublicGrantee and Grant.Audience delegate here.
func classifyGrantee(uri string) Audience {
	if uri == "" {
		return AudiencePrivate
	}
	u := strings.ToLower(uri)
	switch {
	case strings.HasSuffix(u, "/allusers") || strings.HasSuffix(u, ":allusers"):
		return AudienceAllUsers
	case strings.HasSuffix(u, "/authenticatedusers") || strings.HasSuffix(u, ":authenticatedusers"):
		return AudienceAuthenticatedOnly
	default:
		return AudiencePrivate
	}
}

// IsPublicGrantee reports whether a grantee URI matches the S3 AllUsers or
// AuthenticatedUsers group. Uses suffix matching to handle varied input
// sources while avoiding false positives from similarly-named IAM principals.
func IsPublicGrantee(uri string) bool {
	return classifyGrantee(uri) != AudiencePrivate
}
