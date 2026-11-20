package gaps

import "slices"

// Prioritize orders the gap list in place. The ordering matches
// the brief's "intent + tag first, then severity, then chain
// count, then missing count." Stable secondary keys keep the
// output deterministic across runs.
func Prioritize(gaps []FieldGap) {
	slices.SortFunc(gaps, compareGapPriority)
}

func compareGapPriority(a, b FieldGap) int {
	if a.IsIntentProperty != b.IsIntentProperty {
		if a.IsIntentProperty {
			return -1
		}
		return 1
	}
	if a.Remediation.Type != b.Remediation.Type {
		if a.Remediation.Type == RemediationTag {
			return -1
		}
		if b.Remediation.Type == RemediationTag {
			return 1
		}
		if a.Remediation.Type < b.Remediation.Type {
			return -1
		}
		return 1
	}
	if c := b.MaxSeverity.Compare(a.MaxSeverity); c != 0 {
		return c
	}
	if a.ChainsBlockedCount != b.ChainsBlockedCount {
		if a.ChainsBlockedCount > b.ChainsBlockedCount {
			return -1
		}
		return 1
	}
	if a.MissingCount != b.MissingCount {
		if a.MissingCount > b.MissingCount {
			return -1
		}
		return 1
	}
	if a.PropertyPath != b.PropertyPath {
		if a.PropertyPath < b.PropertyPath {
			return -1
		}
		return 1
	}
	if a.AssetType < b.AssetType {
		return -1
	}
	if a.AssetType > b.AssetType {
		return 1
	}
	return 0
}
