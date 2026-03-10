package evaluation

import "github.com/samber/lo"

// VerificationDiff is the deterministic before/after comparison result.
type VerificationDiff struct {
	Resolved   []Finding
	Remaining  []Finding
	Introduced []Finding
}

// CompareVerificationFindings compares before and after findings.
// Returned slices are sorted by control_id then asset_id.
func CompareVerificationFindings(before, after []Finding) VerificationDiff {
	beforeSet := lo.KeyBy(before, verificationFindingKey)
	afterSet := lo.KeyBy(after, verificationFindingKey)

	resolved := make([]Finding, 0)
	remaining := make([]Finding, 0)
	introduced := make([]Finding, 0)

	for key, f := range beforeSet {
		if _, ok := afterSet[key]; !ok {
			resolved = append(resolved, f)
			continue
		}
		remaining = append(remaining, f)
	}

	for key, f := range afterSet {
		if _, ok := beforeSet[key]; !ok {
			introduced = append(introduced, f)
		}
	}

	SortFindings(resolved)
	SortFindings(remaining)
	SortFindings(introduced)

	return VerificationDiff{
		Resolved:   resolved,
		Remaining:  remaining,
		Introduced: introduced,
	}
}

func verificationFindingKey(f Finding) string {
	return f.ControlID.String() + "\x00" + f.AssetID.String()
}
