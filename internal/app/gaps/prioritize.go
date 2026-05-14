package gaps

import (
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
)

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
			return 1
		}
		// 3. Higher max severity wins.
		if a.MaxSeverity != b.MaxSeverity {
			if rank(a.MaxSeverity) > rank(b.MaxSeverity) {
				return -1
			}
			return 1
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
		if a.PropertyPath < b.PropertyPath {
			return -1
		}
		if a.PropertyPath > b.PropertyPath {
			return 1
		}
		return 0
	})
}

func rank(s policy.Severity) int {
	switch s {
	case policy.SeverityCritical:
		return 4
	case policy.SeverityHigh:
		return 3
	case policy.SeverityMedium:
		return 2
	case policy.SeverityLow:
		return 1
	}
	return 0
}
