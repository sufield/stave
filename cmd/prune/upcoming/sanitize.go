package upcoming

import "github.com/sufield/stave/internal/sanitize"

func sanitizeUpcomingItems(s *sanitize.Sanitizer, items []upcomingItem) []upcomingItem {
	out := make([]upcomingItem, len(items))
	for i, item := range items {
		item.AssetID = s.ID(item.AssetID)
		out[i] = item
	}
	return out
}
