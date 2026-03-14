package upcoming

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/sanitize"
)

func sanitizeItems(s *sanitize.Sanitizer, items []Item) []Item {
	if s == nil || len(items) == 0 {
		return items
	}
	out := make([]Item, len(items))
	for i, item := range items {
		item.AssetID = asset.ID(s.ID(string(item.AssetID)))
		out[i] = item
	}
	return out
}
