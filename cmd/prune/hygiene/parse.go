package hygiene

import (
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
)

// toStatuses converts raw CLI flag strings into validated risk.Status values.
// Invalid or empty entries are silently filtered out.
func toStatuses(raw []string) []risk.Status {
	out := make([]risk.Status, 0, len(raw))
	for _, s := range raw {
		trimmed := strings.ToUpper(strings.TrimSpace(s))
		if trimmed == "" {
			continue
		}
		status := risk.Status(trimmed)
		if isValidStatus(status) {
			out = append(out, status)
		}
	}
	return out
}

func isValidStatus(s risk.Status) bool {
	switch s {
	case risk.StatusOverdue, risk.StatusDueNow, risk.StatusUpcoming:
		return true
	default:
		return false
	}
}
