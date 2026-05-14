package kernel

import "errors"

// StatementID identifies a policy statement (SID or synthetic index label).
type StatementID string

func (s StatementID) String() string { return string(s) }

// NewStatementID returns a validated StatementID. Empty statement IDs
// would collide with the "no SID" sentinel that downstream collectors
// use to flag policy statements lacking an explicit identifier.
func NewStatementID(raw string) (StatementID, error) {
	if raw == "" {
		return "", errors.New("statement ID must not be empty")
	}
	return StatementID(raw), nil
}

// GranteeID identifies an ACL grantee (typically a URI).
type GranteeID string

func (s GranteeID) String() string { return string(s) }

// NewGranteeID returns a validated GranteeID. Empty grantee IDs would
// match any ACL row during permission resolution.
func NewGranteeID(raw string) (GranteeID, error) {
	if raw == "" {
		return "", errors.New("grantee ID must not be empty")
	}
	return GranteeID(raw), nil
}

// StringsFrom converts a typed ID slice back to raw strings.
func StringsFrom[T ~string](ids []T) []string {
	if ids == nil {
		return nil
	}
	out := make([]string, len(ids))
	for i := range ids {
		out[i] = string(ids[i])
	}
	return out
}
