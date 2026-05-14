package kernel

import "errors"

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

// NewFindingID returns a validated FindingID. Empty IDs would collide
// across unrelated findings during deduplication and Issue grouping.
// The format itself (sha256[:12] today) is enforced at the derivation
// site in evaluation.StableFindingID, not here — this constructor is
// the boundary check for callers that already hold a derived ID.
func NewFindingID(raw string) (FindingID, error) {
	if raw == "" {
		return "", errors.New("finding ID must not be empty")
	}
	return FindingID(raw), nil
}
