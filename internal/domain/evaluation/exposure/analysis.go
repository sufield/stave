package exposure

// AccessFlags holds the read/write/ACL permission flags shared by
// PolicyAnalysis and ACLAnalysis.
type AccessFlags struct {
	PublicRead            bool
	PublicWrite           bool
	PublicACLRead         bool
	PublicACLWrite        bool
	AuthenticatedRead     bool
	AuthenticatedWrite    bool
	AuthenticatedACLRead  bool
	AuthenticatedACLWrite bool
}

// PolicyAnalysis contains the subset of policy flags used by visibility logic.
type PolicyAnalysis struct {
	AccessFlags
	PublicList        bool
	AuthenticatedList bool
}

// ACLAnalysis contains the subset of ACL flags used by visibility logic.
type ACLAnalysis struct {
	AccessFlags
	PublicFullControl        bool
	AuthenticatedFullControl bool
}

// PublicAccessBlock mirrors bucket/account-level PAB flags.
type PublicAccessBlock struct {
	BlockPublicACLs       bool
	IgnorePublicACLs      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}

// ToPublicMask converts boolean policy flags into a permission bitmask.
func (p PolicyAnalysis) ToPublicMask() Permission {
	var m Permission
	if p.PublicRead {
		m |= PermRead
	}
	if p.PublicWrite {
		m |= PermWrite
	}
	if p.PublicList {
		m |= PermList
	}
	if p.PublicACLRead {
		m |= PermACLRead
	}
	if p.PublicACLWrite {
		m |= PermACLWrite
	}
	return m
}

// ToPublicMask converts boolean ACL flags into a permission bitmask.
func (a ACLAnalysis) ToPublicMask() Permission {
	var m Permission
	if a.PublicRead {
		m |= PermRead
	}
	if a.PublicWrite {
		m |= PermWrite
	}
	if a.PublicACLRead {
		m |= PermACLRead
	}
	if a.PublicACLWrite {
		m |= PermACLWrite
	}
	return m
}

// ResolveEffectivePermissions combines Policy and ACL masks while applying PAB overrides.
func (p PublicAccessBlock) ResolveEffectivePermissions(
	policyMask, aclMask Permission,
) (effective Permission, policyBlocked, aclBlocked bool) {
	policyBlocked = p.BlockPublicPolicy || p.RestrictPublicBuckets
	aclBlocked = p.BlockPublicACLs || p.IgnorePublicACLs

	if !policyBlocked {
		effective |= policyMask
	}
	if !aclBlocked {
		effective |= aclMask
	}
	return effective, policyBlocked, aclBlocked
}

// IsFullyBlocked returns true when all four PAB flags are enabled.
func (p PublicAccessBlock) IsFullyBlocked() bool {
	return p.BlockPublicACLs &&
		p.IgnorePublicACLs &&
		p.BlockPublicPolicy &&
		p.RestrictPublicBuckets
}
