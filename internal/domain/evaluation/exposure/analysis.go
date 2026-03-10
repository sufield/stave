package exposure

// AccessFlags holds the read/write/ACL permission flags shared by
// PolicyAnalysis and ACLAnalysis.
type AccessFlags struct {
	AllowsPublicRead            bool
	AllowsPublicWrite           bool
	AllowsPublicACLRead         bool
	AllowsPublicACLWrite        bool
	AllowsAuthenticatedRead     bool
	AllowsAuthenticatedWrite    bool
	AllowsAuthenticatedACLRead  bool
	AllowsAuthenticatedACLWrite bool
}

// PolicyAnalysis contains the subset of policy flags used by visibility logic.
type PolicyAnalysis struct {
	AccessFlags
	AllowsPublicList        bool
	AllowsAuthenticatedList bool
}

// ACLAnalysis contains the subset of ACL flags used by visibility logic.
type ACLAnalysis struct {
	AccessFlags
	HasFullControlPublic        bool
	HasFullControlAuthenticated bool
}

// PublicAccessBlock mirrors bucket/account-level PAB flags.
type PublicAccessBlock struct {
	BlockPublicAcls       bool
	IgnorePublicAcls      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}

// IsFullyBlocked returns true when all four PAB flags are enabled.
func (p PublicAccessBlock) IsFullyBlocked() bool {
	return p.BlockPublicAcls &&
		p.IgnorePublicAcls &&
		p.BlockPublicPolicy &&
		p.RestrictPublicBuckets
}
