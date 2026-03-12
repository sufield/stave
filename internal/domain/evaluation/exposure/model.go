package exposure

// Capabilities represents a normalized set of actions an external
// entity can perform on a resource.
type Capabilities struct {
	Read   bool
	Write  bool
	List   bool
	Delete bool
	Admin  bool // e.g., Read/Write Permissions (ACLs/Policies)
}

// ToMask converts boolean flags into a portable Permission bitmask.
func (c Capabilities) ToMask() Permission {
	var m Permission
	if c.Read {
		m |= PermRead
	}
	if c.Write {
		m |= PermWrite
	}
	if c.List {
		m |= PermList
	}
	if c.Delete {
		m |= PermDelete
	}
	if c.Admin {
		m |= PermMetadataRead | PermMetadataWrite
	}
	return m
}

// IsFullControl returns true when all capabilities are granted.
func (c Capabilities) IsFullControl() bool {
	return c.Read && c.Write && c.List && c.Delete && c.Admin
}

// Visibility represents who can access the resource.
type Visibility struct {
	Public        Capabilities
	Authenticated Capabilities
}

// GovernanceOverrides represents global security settings that
// trump individual resource settings (e.g., AWS Public Access Block).
type GovernanceOverrides struct {
	BlockResourceBoundPublicAccess bool
	BlockIdentityBoundPublicAccess bool
	EnforceStrictPublicInheritance bool
}

// IsHardened returns true if the most restrictive security posture is applied.
func (gov GovernanceOverrides) IsHardened() bool {
	return gov.BlockResourceBoundPublicAccess &&
		gov.BlockIdentityBoundPublicAccess &&
		gov.EnforceStrictPublicInheritance
}
