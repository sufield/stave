package upcoming

import (
	"time"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
)

func mapRiskItems(items risk.Items) []Item {
	if len(items) == 0 {
		return nil
	}
	out := make([]Item, len(items))
	for i, d := range items {
		out[i] = Item{
			DueAt:          d.DueAt,
			Status:         d.Status,
			ControlID:      d.ControlID,
			AssetID:        d.AssetID,
			AssetType:      d.AssetType,
			FirstUnsafeAt:  d.FirstUnsafeAt,
			LastSeenUnsafe: d.LastSeenUnsafe,
			Threshold:      d.Threshold,
			Remaining:      d.Remaining,
		}
	}
	return out
}

func summarizeUpcoming(items []Item, dueSoonThreshold time.Duration) Summary {
	// Convert to risk.Items for canonical summarization.
	riskItems := make(risk.Items, len(items))
	for i, item := range items {
		riskItems[i] = risk.Item{
			Status:    item.Status,
			Remaining: item.Remaining,
		}
	}
	s := riskItems.Summarize(dueSoonThreshold)
	return Summary{
		Overdue: s.Overdue,
		DueNow:  s.DueNow,
		DueSoon: s.DueSoon,
		Later:   s.Later,
		Total:   s.Total,
	}
}
