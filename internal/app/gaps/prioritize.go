package gaps

import "slices"

// Prioritize orders the gap list in place. The ordering matches
// the brief's "intent + tag first, then severity, then chain
// count, then missing count." Stable secondary keys keep the
// output deterministic across runs.
func Prioritize(gaps []FieldGap) {
	slices.SortFunc(gaps, func(a, b FieldGap) int {
		// 1. Intent properties first (tags + highest unlock
		//    per effort).
		if a.IsIntentProperty != b.IsIntentProperty {
			if a.IsIntentProperty {
				return -1
			}
			return 1
		}
		// 2. Tag gaps before collector gaps (lower effort).
		if a.Remediation.Type != b.Remediation.Type {
			if a.Remediation.Type == "tag" {
				return -1
			}
			if b.Remediation.Type == "tag" {
				return 1
			}
			if a.Remediation.Type < b.Remediation.Type {
				return -1
			}
			return 1
		}
		// 3. Higher max severity wins. Delegate to the canonical
		//    Severity.Compare ladder rather than a local rank table that
		//    could drift if a tier is added/renamed; b-then-a is descending
		//    (more-critical first).
		if c := b.MaxSeverity.Compare(a.MaxSeverity); c != 0 {
			return c
		}
		// 4. More chains blocked wins.
		if a.ChainsBlockedCount != b.ChainsBlockedCount {
			if a.ChainsBlockedCount > b.ChainsBlockedCount {
				return -1
			}
			return 1
		}
		// 5. More assets affected wins.
		if a.MissingCount != b.MissingCount {
			if a.MissingCount > b.MissingCount {
				return -1
			}
			return 1
		}
		// 6. Stable alphabetical fallback.
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
	})
}
