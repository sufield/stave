package kernel

import "errors"

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

// NewChainID returns a validated ChainID. The empty string is the
// foot-gun this constructor exists to prevent — chain IDs feed into
// equality checks across compound-risk evaluation, and an empty value
// silently matches every other empty-default field.
func NewChainID(raw string) (ChainID, error) {
	if raw == "" {
		return "", errors.New("chain ID must not be empty")
	}
	return ChainID(raw), nil
}
