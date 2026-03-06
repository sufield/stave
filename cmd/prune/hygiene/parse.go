package hygiene

import (
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
)

func toControlIDs(raw []string) []kernel.ControlID {
	out := make([]kernel.ControlID, 0, len(raw))
	for _, s := range raw {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, kernel.ControlID(trimmed))
		}
	}
	return out
}

func toResourceTypes(raw []string) []kernel.AssetType {
	out := make([]kernel.AssetType, 0, len(raw))
	for _, s := range raw {
		if rt := kernel.NewAssetType(s); rt != "" {
			out = append(out, rt)
		}
	}
	return out
}

func toStatuses(raw []string) []risk.Status {
	out := make([]risk.Status, 0, len(raw))
	for _, s := range raw {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, risk.Status(strings.ToUpper(trimmed)))
		}
	}
	return out
}
