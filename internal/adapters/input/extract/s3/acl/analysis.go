package acl

// Entry wraps raw S3 ACL grants and exposes high-level access predicates.
type Entry struct {
	grants []Grant
}

// Analysis contains the analysis results of S3 ACL grants.
type Analysis struct {
	AllowsPublicRead  bool     // READ to AllUsers
	AllowsPublicWrite bool     // WRITE to AllUsers
	PublicGrantees    []string // URIs of public grantees found

	// Authenticated-only access (AuthenticatedUsers grantee, not AllUsers)
	AllowsAuthenticatedRead  bool
	AllowsAuthenticatedWrite bool

	// ACL permission grants (READ_ACP, WRITE_ACP)
	AllowsPublicACLRead         bool // READ_ACP to AllUsers
	AllowsPublicACLWrite        bool // WRITE_ACP to AllUsers
	AllowsAuthenticatedACLRead  bool // READ_ACP to AuthenticatedUsers
	AllowsAuthenticatedACLWrite bool // WRITE_ACP to AuthenticatedUsers

	// FULL_CONTROL explicit grants (distinct from individual read+write)
	HasFullControlPublic        bool // FULL_CONTROL to AllUsers
	HasFullControlAuthenticated bool // FULL_CONTROL to AuthenticatedUsers
}

// AllUsersGranteeURI is the AWS S3 ACL grantee identifier for anonymous/public access.
// This is an opaque identifier defined by AWS, NOT an HTTP endpoint — Stave never fetches this URL.
// See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#specifying-grantee
const AllUsersGranteeURI = "http://acs.amazonaws.com/groups/global/AllUsers"

// AuthenticatedUsersGranteeURI is the AWS S3 ACL grantee identifier for any authenticated AWS user.
// This is an opaque identifier defined by AWS, NOT an HTTP endpoint — Stave never fetches this URL.
const AuthenticatedUsersGranteeURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

type Permission uint8

const (
	aclPermRead Permission = 1 << iota
	aclPermWrite
	aclPermReadACP
	aclPermWriteACP

	aclPermFullControl = aclPermRead | aclPermWrite | aclPermReadACP | aclPermWriteACP
)

var aclPermissionByString = map[string]Permission{
	permRead:        aclPermRead,
	permWrite:       aclPermWrite,
	permReadACL:     aclPermReadACP,
	permWriteACL:    aclPermWriteACP,
	permFullControl: aclPermFullControl,
}

func (p Permission) has(target Permission) bool {
	return p&target != 0
}

// NewEntry constructs an Entry wrapper over grants.
func NewEntry(grants []Grant) *Entry {
	if len(grants) == 0 {
		return &Entry{}
	}
	copied := make([]Grant, len(grants))
	copy(copied, grants)
	return &Entry{grants: copied}
}

// Grants returns a defensive copy of grants to avoid leaking mutable internals.
func (a *Entry) Grants() []Grant {
	if a == nil || len(a.grants) == 0 {
		return nil
	}
	copied := make([]Grant, len(a.grants))
	copy(copied, a.grants)
	return copied
}

// Summary holds the reduced permission sets from ACL grant analysis.
type Summary struct {
	AllUsersPerms               Permission
	AuthOnlyPerms               Permission
	PublicGrantees              []string
	HasFullControlPublic        bool
	HasFullControlAuthenticated bool
}

// Summarize reduces grants into all-users and authenticated-only permission sets.
func (a *Entry) Summarize() Summary {
	if a == nil {
		return Summary{}
	}

	s := Summary{
		PublicGrantees: Grants(a.grants).PublicGrantees(),
	}
	for _, grant := range a.grants {
		audience := grant.Audience()
		if audience == AudiencePrivate {
			continue
		}

		perms := grant.Permissions()
		fullControl := grant.HasFullControl()

		switch audience {
		case AudienceAllUsers:
			s.AllUsersPerms |= perms
			if fullControl {
				s.HasFullControlPublic = true
			}
		case AudienceAuthenticatedOnly:
			s.AuthOnlyPerms |= perms
			if fullControl {
				s.HasFullControlAuthenticated = true
			}
		}
	}

	return s
}

// Analyze returns the ACL analysis for the wrapped grants.
func (a *Entry) Analyze() Analysis {
	s := a.Summarize()
	return Analysis{
		PublicGrantees: s.PublicGrantees,

		// Public means anonymous (AllUsers), not authenticated-only.
		AllowsPublicRead:  s.AllUsersPerms.has(aclPermRead),
		AllowsPublicWrite: s.AllUsersPerms.has(aclPermWrite),

		AllowsAuthenticatedRead:  s.AuthOnlyPerms.has(aclPermRead),
		AllowsAuthenticatedWrite: s.AuthOnlyPerms.has(aclPermWrite),

		// Preserve existing semantics: "public ACL read/write" are all-users only.
		AllowsPublicACLRead:  s.AllUsersPerms.has(aclPermReadACP),
		AllowsPublicACLWrite: s.AllUsersPerms.has(aclPermWriteACP),

		AllowsAuthenticatedACLRead:  s.AuthOnlyPerms.has(aclPermReadACP),
		AllowsAuthenticatedACLWrite: s.AuthOnlyPerms.has(aclPermWriteACP),

		HasFullControlPublic:        s.HasFullControlPublic,
		HasFullControlAuthenticated: s.HasFullControlAuthenticated,
	}
}

// Analyze analyzes S3 ACL grants for public access.
func Analyze(grants []Grant) Analysis {
	return NewEntry(grants).Analyze()
}

// IsPublicGrantee checks if a grantee URI represents public access.
func IsPublicGrantee(granteeURI string) bool {
	return Grant{Grantee: granteeURI}.IsPublic()
}
