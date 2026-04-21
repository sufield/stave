package kernel

// FindingID is the stable per-(control, asset) fingerprint emitted by
// the evaluation engine. Defined as a typed string so collections of
// member finding IDs (Issue.MemberFindingIDs) carry the same type as
// individual Finding.FindingID values, eliminating the
// string(f.FindingID) cast pattern at consumer sites.
//
// See evaluation.StableFindingID for the derivation. JSON
// serialization is identical to a raw string.
type FindingID string

// String returns the raw ID string.
func (id FindingID) String() string {
	return string(id)
}
