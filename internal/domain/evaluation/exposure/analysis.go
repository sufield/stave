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

// IsFullyBlocked returns true when all four PAB flags are enabled.
func (p PublicAccessBlock) IsFullyBlocked() bool {
	return p.BlockPublicACLs &&
		p.IgnorePublicACLs &&
		p.BlockPublicPolicy &&
		p.RestrictPublicBuckets
}
