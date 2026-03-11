package exposure

import "strings"

const (
	policyWildcard = "*"
)

const (
	principalTokenAllUsers           = "allusers"
	principalTokenAuthenticatedUsers = "authenticatedusers"
)

// Permission is the internal permission bitmask used by
// visibility resolution and exposure classification.
type Permission uint32

const (
	PermRead Permission = 1 << iota
	PermWrite
	PermList
	PermACLRead
	PermACLWrite
	PermDelete

	PermAll = PermRead | PermWrite | PermList | PermACLRead | PermACLWrite | PermDelete
)

// Has reports whether target bits are set in p.
func (p Permission) Has(target Permission) bool { return p&target != 0 }

// EvidenceCategory provides type safety for tracking why an exposure was flagged.
type EvidenceCategory string

const (
	EvPolicyRead     EvidenceCategory = "policy_read"
	EvACLRead        EvidenceCategory = "acl_read"
	EvPolicyWrite    EvidenceCategory = "policy_write"
	EvACLWrite       EvidenceCategory = "acl_write"
	EvList           EvidenceCategory = "list"
	EvACLReadPolicy  EvidenceCategory = "acl_read_policy"
	EvACLWritePolicy EvidenceCategory = "acl_write_policy"
	EvDelete         EvidenceCategory = "delete"
)

// actionToPerm maps S3 Action strings to internal permission bits.
var actionToPerm = map[string]Permission{
	"*":                     PermAll,
	"s3:*":                  PermAll,
	"s3:getobject":          PermRead,
	"s3:putobject":          PermWrite,
	"s3:listbucket":         PermList,
	"s3:listbucketversions": PermList,
	"s3:getbucketacl":       PermACLRead,
	"s3:getobjectacl":       PermACLRead,
	"s3:putbucketacl":       PermACLWrite,
	"s3:putobjectacl":       PermACLWrite,
	"s3:deleteobject":       PermDelete,
	"s3:deletebucket":       PermDelete,
}

type permissionSet struct {
	Get      bool
	Put      bool
	List     bool
	ACLRead  bool
	ACLWrite bool
	Delete   bool
}

func (p permissionSet) merged(other permissionSet) permissionSet {
	return permissionSet{
		Get:      p.Get || other.Get,
		Put:      p.Put || other.Put,
		List:     p.List || other.List,
		ACLRead:  p.ACLRead || other.ACLRead,
		ACLWrite: p.ACLWrite || other.ACLWrite,
		Delete:   p.Delete || other.Delete,
	}
}

type writeSourceState struct {
	HasGet  bool
	HasList bool
}

// EvidenceTracker manages the paths/reasons for discovered exposures.
type EvidenceTracker struct {
	sources map[EvidenceCategory][]string
}

// NewEvidenceTracker creates an initialized EvidenceTracker.
func NewEvidenceTracker() *EvidenceTracker {
	return &EvidenceTracker{sources: make(map[EvidenceCategory][]string)}
}

// Record stores the first (most relevant) evidence for a category.
func (t *EvidenceTracker) Record(cat EvidenceCategory, path []string) {
	if len(path) == 0 {
		return
	}
	if _, exists := t.sources[cat]; !exists {
		t.sources[cat] = path
	}
}

// Get returns the evidence path for a category.
func (t *EvidenceTracker) Get(cat EvidenceCategory) []string {
	return t.sources[cat]
}

type bucketResolutionContext struct {
	input ExposureBucketInput

	hasAuthenticatedOnly bool
	policyPerms          permissionSet
	aclPerms             permissionSet
	writeSource          writeSourceState
	evidence             *EvidenceTracker
}

// IsAllUsers reports whether this grant applies to all users.
func (g ACLGrant) IsAllUsers() bool {
	return strings.Contains(strings.ToLower(g.Grantee), principalTokenAllUsers)
}

// IsAuthenticatedUsers reports whether this grant applies to authenticated users.
func (g ACLGrant) IsAuthenticatedUsers() bool {
	return strings.Contains(strings.ToLower(g.Grantee), principalTokenAuthenticatedUsers)
}

// IsPublic reports whether this grant applies to AllUsers or AuthenticatedUsers.
func (g ACLGrant) IsPublic() bool {
	grantee := strings.ToLower(g.Grantee)
	return strings.Contains(grantee, principalTokenAllUsers) ||
		strings.Contains(grantee, principalTokenAuthenticatedUsers)
}

// ExposurePermissions converts the ACL string representation into a bitmask.
func (g ACLGrant) ExposurePermissions() Permission {
	perm := strings.ToUpper(strings.TrimSpace(g.Permission))
	scope := strings.ToLower(strings.TrimSpace(g.Scope))

	if perm == "FULL_CONTROL" {
		return PermAll
	}

	switch perm {
	case "READ":
		if scope == "bucket" {
			return PermList
		}
		return PermRead
	case "WRITE":
		return PermWrite
	case "READ_ACP":
		return PermACLRead
	case "WRITE_ACP":
		return PermACLWrite
	default:
		return 0
	}
}

func isAuthenticatedUsersPrincipalToken(value string) bool {
	return strings.Contains(strings.ToLower(value), principalTokenAuthenticatedUsers)
}
