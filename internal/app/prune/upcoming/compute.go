package upcoming

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

func mapRiskItems(items risk.Items) []UpcomingSnapshot {
	if len(items) == 0 {
		return nil
	}
	out := make([]UpcomingSnapshot, len(items))
	for i, d := range items {
		out[i] = UpcomingSnapshot{
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

func summarizeUpcoming(items []UpcomingSnapshot, dueSoonThreshold time.Duration) UpcomingSummary {
	// Convert to risk.Items for canonical summarization.
	riskItems := make(risk.Items, len(items))
	for i, item := range items {
		riskItems[i] = risk.Item{
			Status:    item.Status,
			Remaining: item.Remaining,
		}
	}
	s := riskItems.Summarize(dueSoonThreshold)
	return UpcomingSummary{
		Overdue: s.Overdue,
		DueNow:  s.DueNow,
		DueSoon: s.DueSoon,
		Later:   s.Later,
		Total:   s.Total,
	}
}
