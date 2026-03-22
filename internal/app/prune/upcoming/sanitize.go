package upcoming

import (
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func sanitizeItems(s kernel.Sanitizer, items []UpcomingSnapshot) []UpcomingSnapshot {
	if s == nil || len(items) == 0 {
		return items
	}
	out := make([]UpcomingSnapshot, len(items))
	for i, item := range items {
		item.AssetID = asset.ID(s.ID(string(item.AssetID)))
		out[i] = item
	}
	return out
}
