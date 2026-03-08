package cmdutil

import (
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

// ToControlIDs converts a string slice to kernel.ControlID slice,
// trimming whitespace and skipping empty entries.
func ToControlIDs(raw []string) []kernel.ControlID {
	out := make([]kernel.ControlID, 0, len(raw))
	for _, s := range raw {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, kernel.ControlID(trimmed))
		}
	}
	return out
}

// ToAssetTypes converts a string slice to kernel.AssetType slice,
// skipping entries that produce an empty AssetType.
func ToAssetTypes(raw []string) []kernel.AssetType {
	out := make([]kernel.AssetType, 0, len(raw))
	for _, s := range raw {
		if rt := kernel.NewAssetType(s); rt != "" {
			out = append(out, rt)
		}
	}
	return out
}
