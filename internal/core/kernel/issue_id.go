package kernel

import "errors"

// IssueID is the stable per-(asset, shared-keys, headline-control)
// fingerprint for a consolidated Issue. Same triple → same ID across
// runs. Defined as a typed string so consumers comparing or
// collecting IssueID values keep semantic meaning instead of
// degrading to []string.
//
// JSON serialization is identical to a raw string.
type IssueID string

// String returns the raw ID string.
func (id IssueID) String() string { return string(id) }

// NewIssueID returns a validated IssueID. Empty IDs would silently
// merge unrelated issues during consolidation.
func NewIssueID(raw string) (IssueID, error) {
	if raw == "" {
		return "", errors.New("issue ID must not be empty")
	}
	return IssueID(raw), nil
}
