package upcoming

import (
	"time"

	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/policy"
)

func computeUpcomingItems(
	snapshots []asset.Snapshot,
	controls []policy.ControlDefinition,
	opts UpcomingComputeOptions,
) []UpcomingItem {
	domainItems := risk.ComputeItems(risk.Request{
		Controls:        controls,
		Snapshots:       snapshots,
		GlobalMaxUnsafe: opts.GlobalMaxUnsafe,
		Now:             opts.Now,
		PredicateParser: ctlyaml.YAMLPredicateParser,
	})
	items := make([]UpcomingItem, 0, len(domainItems))
	for _, d := range domainItems {
		items = append(items, UpcomingItem{
			DueAt:          d.DueAt,
			Status:         string(d.Status),
			ControlID:      string(d.ControlID),
			AssetID:        string(d.AssetID),
			AssetType:      string(d.AssetType),
			FirstUnsafeAt:  d.FirstUnsafeAt,
			LastSeenUnsafe: d.LastSeenUnsafe,
			Threshold:      d.Threshold,
			Remaining:      d.Remaining,
		})
	}
	return items
}

func summarizeUpcoming(items []UpcomingItem, dueSoonThreshold time.Duration) UpcomingSummary {
	var s UpcomingSummary
	s.Total = len(items)
	for _, item := range items {
		switch item.Status {
		case "OVERDUE":
			s.Overdue++
		case "DUE_NOW":
			s.DueNow++
		default:
			if item.Remaining > 0 && item.Remaining <= dueSoonThreshold {
				s.DueSoon++
			} else {
				s.Later++
			}
		}
	}
	return s
}
