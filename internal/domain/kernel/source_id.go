package kernel

// SourceID is a generic, opaque identifier for a configuration source.
// It could be a Statement ID (SID), a Grantee URI, or an array index.
type SourceID string

func (s SourceID) String() string { return string(s) }

// StatementID identifies a policy statement (SID or synthetic index label).
type StatementID SourceID

func (s StatementID) String() string { return string(s) }

// GranteeID identifies an ACL grantee (typically a URI).
type GranteeID SourceID

func (s GranteeID) String() string { return string(s) }

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
