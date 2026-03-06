package exposure

import "strings"

const (
	policyWildcard                 = "*"
	policyS3Wildcard               = "s3:*"
	policyActionGetObject          = "s3:getobject"
	policyActionListBucket         = "s3:listbucket"
	policyActionListBucketVersions = "s3:listbucketversions"
	policyActionPutObject          = "s3:putobject"
	policyActionPutObjectACL       = "s3:putobjectacl"
	policyActionDeleteObject       = "s3:deleteobject"
	policyActionDeleteBucket       = "s3:deletebucket"
	policyActionPutBucketACL       = "s3:putbucketacl"
	policyActionGetBucketACL       = "s3:getbucketacl"
	policyActionGetObjectACL       = "s3:getobjectacl"
)

const (
	principalTokenAllUsers           = "allusers"
	principalTokenAuthenticatedUsers = "authenticatedusers"
)

const (
	permRead        = "READ"
	permWrite       = "WRITE"
	permReadACL     = "READ_ACP"
	permWriteACL    = "WRITE_ACP"
	permFullControl = "FULL_CONTROL"

	scopeObject = "object"
	scopeBucket = "bucket"
)

const (
	evidencePolicyRead     = "policy_read"
	evidenceACLRead        = "acl_read"
	evidencePolicyWrite    = "policy_write"
	evidenceACLWrite       = "acl_write"
	evidenceList           = "list"
	evidenceACLReadPolicy  = "acl_read_policy"
	evidenceACLWritePolicy = "acl_write_policy"
	evidenceDelete         = "delete"
)

// accessPermissionMask is the shared internal permission bitmask used by
// visibility resolution and exposure classification.
type accessPermissionMask uint32

const (
	accessPermRead accessPermissionMask = 1 << iota
	accessPermWrite
	accessPermList
	accessPermACLRead
	accessPermACLWrite
	accessPermDelete

	accessPermAll = accessPermRead | accessPermWrite | accessPermList | accessPermACLRead | accessPermACLWrite | accessPermDelete
)

func (m accessPermissionMask) has(target accessPermissionMask) bool {
	return m&target != 0
}

type statementPermission = accessPermissionMask

const (
	stmtPermRead  statementPermission = accessPermRead
	stmtPermWrite statementPermission = accessPermWrite
	stmtPermList  statementPermission = accessPermList

	stmtPermACLRead  statementPermission = accessPermACLRead
	stmtPermACLWrite statementPermission = accessPermACLWrite
	stmtPermDelete   statementPermission = accessPermDelete

	stmtPermAll statementPermission = accessPermAll
)

var actionToPermission = map[string]statementPermission{
	policyWildcard:                 stmtPermAll,
	policyS3Wildcard:               stmtPermAll,
	policyActionGetObject:          stmtPermRead,
	policyActionPutObject:          stmtPermWrite,
	policyActionListBucket:         stmtPermList,
	policyActionGetBucketACL:       stmtPermACLRead,
	policyActionGetObjectACL:       stmtPermACLRead,
	policyActionPutBucketACL:       stmtPermACLWrite,
	policyActionPutObjectACL:       stmtPermACLWrite,
	policyActionDeleteObject:       stmtPermDelete,
	policyActionDeleteBucket:       stmtPermDelete,
	policyActionListBucketVersions: stmtPermList,
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

type evidenceTracker struct {
	sources map[string][]string
}

func newEvidenceTracker() evidenceTracker {
	return evidenceTracker{sources: make(map[string][]string)}
}

func (t *evidenceTracker) Record(category string, path []string) {
	if len(path) == 0 {
		return
	}
	if _, exists := t.sources[category]; exists {
		return
	}
	t.sources[category] = path
}

func (t *evidenceTracker) Get(category string) []string {
	return t.sources[category]
}

type bucketResolutionContext struct {
	input ExposureBucketInput

	hasAuthenticatedOnly bool
	policyPerms          permissionSet
	aclPerms             permissionSet
	writeSource          writeSourceState
	evidence             evidenceTracker
}

func (g ACLGrant) normalizedGrantee() string {
	return strings.ToLower(strings.TrimSpace(g.Grantee))
}

func (g ACLGrant) normalizedPermission() string {
	return strings.ToUpper(strings.TrimSpace(g.Permission))
}

func (g ACLGrant) normalizedScope() string {
	return strings.ToLower(strings.TrimSpace(g.Scope))
}

// IsAllUsers reports whether this grant applies to all users.
func (g ACLGrant) IsAllUsers() bool {
	return strings.Contains(g.normalizedGrantee(), principalTokenAllUsers)
}

// IsAuthenticatedUsers reports whether this grant applies to authenticated users.
func (g ACLGrant) IsAuthenticatedUsers() bool {
	return strings.Contains(g.normalizedGrantee(), principalTokenAuthenticatedUsers)
}

// IsPublic reports whether this grant applies to any public principal.
func (g ACLGrant) IsPublic() bool {
	return g.IsAllUsers() || g.IsAuthenticatedUsers()
}

// HasFullControl reports whether this grant provides FULL_CONTROL permission.
func (g ACLGrant) HasFullControl() bool {
	return g.normalizedPermission() == permFullControl
}

// ExposurePermissions returns the permission bitmask for this grant.
func (g ACLGrant) ExposurePermissions() accessPermissionMask {
	switch {
	case g.HasFullControl():
		return accessPermAll
	case g.normalizedPermission() == permRead && g.normalizedScope() == scopeObject:
		return accessPermRead
	case g.normalizedPermission() == permRead && g.normalizedScope() == scopeBucket:
		return accessPermList
	case g.normalizedPermission() == permWrite:
		return accessPermWrite
	case g.normalizedPermission() == permReadACL:
		return accessPermACLRead
	case g.normalizedPermission() == permWriteACL:
		return accessPermACLWrite
	default:
		return 0
	}
}

func isAuthenticatedUsersPrincipalToken(value string) bool {
	return strings.Contains(strings.ToLower(value), principalTokenAuthenticatedUsers)
}

func policyPublicMask(policy PolicyAnalysis) accessPermissionMask {
	var mask accessPermissionMask
	if policy.AllowsPublicRead {
		mask |= accessPermRead
	}
	if policy.AllowsPublicWrite {
		mask |= accessPermWrite
	}
	if policy.AllowsPublicList {
		mask |= accessPermList
	}
	if policy.AllowsPublicACLRead {
		mask |= accessPermACLRead
	}
	if policy.AllowsPublicACLWrite {
		mask |= accessPermACLWrite
	}
	return mask
}

func aclPublicMask(acl ACLAnalysis) accessPermissionMask {
	var mask accessPermissionMask
	if acl.AllowsPublicRead {
		mask |= accessPermRead
	}
	if acl.AllowsPublicWrite {
		mask |= accessPermWrite
	}
	if acl.AllowsPublicACLRead {
		mask |= accessPermACLRead
	}
	if acl.AllowsPublicACLWrite {
		mask |= accessPermACLWrite
	}
	return mask
}

func applyPublicAccessBlock(
	policyMask, aclMask accessPermissionMask,
	pab PublicAccessBlock,
) (effectiveMask accessPermissionMask, policyBlocked, aclBlocked bool) {
	policyBlocked = pab.BlockPublicPolicy || pab.RestrictPublicBuckets
	aclBlocked = pab.BlockPublicAcls || pab.IgnorePublicAcls

	if !policyBlocked {
		effectiveMask |= policyMask
	}
	if !aclBlocked {
		effectiveMask |= aclMask
	}
	return effectiveMask, policyBlocked, aclBlocked
}
