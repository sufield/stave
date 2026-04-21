package kernel

// ChainID identifies a compound-risk chain definition (e.g.
// "privilege_escalation_path"). Typed string so collections of
// chain IDs (e.g. ChainMembershipEntry fields) can be compared
// directly with individual ChainFinding.ChainID values, paralleling
// the kernel.FindingID precedent.
//
// JSON serialization is identical to a raw string.
type ChainID string

// String returns the raw ID string.
func (id ChainID) String() string {
	return string(id)
}
