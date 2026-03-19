package acl

import (
	"slices"

	"github.com/sufield/stave/internal/domain/kernel"
)

// AWS Canonical Group URIs.
// These are opaque identifiers defined by AWS, NOT HTTP endpoints — Stave never fetches them.
// See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee
const (
	AllUsersGranteeURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	AuthenticatedUsersGranteeURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// Permission represents a bitmask of S3 ACL permissions (READ, WRITE, etc.)
type Permission uint8

const (
	aclPermRead Permission = 1 << iota
	aclPermWrite
	aclPermReadACP
	aclPermWriteACP

	aclPermFullControl = aclPermRead | aclPermWrite | aclPermReadACP | aclPermWriteACP
)

func (p Permission) has(target Permission) bool {
	return p&target != 0
}

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
	AllowsPublicRead  bool               // READ to AllUsers
	AllowsPublicWrite bool               // WRITE to AllUsers
	PublicGrantees    []kernel.GranteeID // URIs of public groups found

	// Authenticated-only access (AuthenticatedUsers grantee, NOT AllUsers)
	AllowsAuthenticatedRead  bool
	AllowsAuthenticatedWrite bool

	// ACL metadata permission grants (READ_ACP, WRITE_ACP)
	AllowsPublicACLRead         bool // READ_ACP to AllUsers
	AllowsPublicACLWrite        bool // WRITE_ACP to AllUsers
	AllowsAuthenticatedACLRead  bool // READ_ACP to AuthenticatedUsers
	AllowsAuthenticatedACLWrite bool // WRITE_ACP to AuthenticatedUsers

	// FULL_CONTROL explicit grants (distinct from individual read+write)
	HasFullControlPublic        bool // FULL_CONTROL to AllUsers
	HasFullControlAuthenticated bool // FULL_CONTROL to AuthenticatedUsers
}

// Assess evaluates the ACL grants and returns a summary of effective permissions.
func (l List) Assess() Assessment {
	var (
		allUsersPerms  Permission
		authUsersPerms Permission
		publicIDs      []kernel.GranteeID
		fullPublic     bool
		fullAuth       bool
	)

	for _, g := range l.grants {
		audience := g.Audience()
		if audience == AudiencePrivate {
			continue
		}

		perms := g.Permissions()
		hasFC := g.HasFullControl()

		switch audience {
		case AudienceAllUsers:
			allUsersPerms |= perms
			if hasFC {
				fullPublic = true
			}
			publicIDs = append(publicIDs, kernel.GranteeID(g.Grantee))
		case AudienceAuthenticatedOnly:
			authUsersPerms |= perms
			if hasFC {
				fullAuth = true
			}
		}
	}

	return Assessment{
		PublicGrantees: publicIDs,

		AllowsPublicRead:  allUsersPerms.has(aclPermRead),
		AllowsPublicWrite: allUsersPerms.has(aclPermWrite),

		AllowsAuthenticatedRead:  authUsersPerms.has(aclPermRead),
		AllowsAuthenticatedWrite: authUsersPerms.has(aclPermWrite),

		AllowsPublicACLRead:  allUsersPerms.has(aclPermReadACP),
		AllowsPublicACLWrite: allUsersPerms.has(aclPermWriteACP),

		AllowsAuthenticatedACLRead:  authUsersPerms.has(aclPermReadACP),
		AllowsAuthenticatedACLWrite: authUsersPerms.has(aclPermWriteACP),

		HasFullControlPublic:        fullPublic,
		HasFullControlAuthenticated: fullAuth,
	}
}

// Assess is a package-level convenience for one-off grant evaluation.
func Assess(grants []Grant) Assessment {
	return New(grants).Assess()
}

// IsPublicGrantee checks if a grantee URI represents public access.
func IsPublicGrantee(granteeURI string) bool {
	return Grant{Grantee: granteeURI}.IsPublic()
}
