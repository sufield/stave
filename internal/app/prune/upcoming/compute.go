package upcoming

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

func mapRiskItems(items risk.ThresholdItems) []UpcomingSnapshot {
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

func summarizeUpcoming(items []UpcomingSnapshot, dueSoonThreshold time.Duration) UpcomingSummary {
	// Convert to risk.ThresholdItems for canonical summarization.
	riskItems := make(risk.ThresholdItems, len(items))
	for i, item := range items {
		riskItems[i] = risk.ThresholdItem{
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
