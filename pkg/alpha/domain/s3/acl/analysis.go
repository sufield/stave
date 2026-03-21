package acl

import (
	"slices"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// AWS Canonical Group URIs.
// These are opaque identifiers defined by AWS, NOT HTTP endpoints — Stave never fetches them.
// See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee
const (
	allUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	authenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// List represents an S3 Access Control List as a collection of grants.
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
	perms := make(map[Audience]risk.Permission)
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

// IsPublicGrantee checks if a grantee URI represents public access.
func IsPublicGrantee(granteeURI string) bool {
	return matchesToken(granteeURI, "allusers") ||
		matchesToken(granteeURI, "authenticatedusers")
}
