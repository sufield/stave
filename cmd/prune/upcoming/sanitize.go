package upcoming

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/sanitize"
)

func sanitizeUpcomingItems(s *sanitize.Sanitizer, items []UpcomingItem) []UpcomingItem {
	out := make([]UpcomingItem, len(items))
	for i, item := range items {
		item.AssetID = asset.ID(s.ID(string(item.AssetID)))
		out[i] = item
	}
	return out
}
