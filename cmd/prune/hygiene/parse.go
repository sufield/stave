package hygiene

import (
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
)

func toStatuses(raw []string) []risk.Status {
	out := make([]risk.Status, 0, len(raw))
	for _, s := range raw {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, risk.Status(strings.ToUpper(trimmed)))
		}
	}
	return out
}
