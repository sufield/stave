package hygiene

import (
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/risk"
)

// toStatuses converts raw CLI flag strings into validated risk.ThresholdStatus values.
// Invalid or empty entries are silently filtered out.
func toStatuses(raw []string) []risk.ThresholdStatus {
	out := make([]risk.ThresholdStatus, 0, len(raw))
	for _, s := range raw {
		trimmed := strings.ToUpper(strings.TrimSpace(s))
		if trimmed == "" {
			continue
		}
		status := risk.ThresholdStatus(trimmed)
		if isValidStatus(status) {
			out = append(out, status)
		}
	}
	return out
}

func isValidStatus(s risk.ThresholdStatus) bool {
	switch s {
	case risk.StatusOverdue, risk.StatusDueNow, risk.StatusUpcoming:
		return true
	default:
		return false
	}
}
