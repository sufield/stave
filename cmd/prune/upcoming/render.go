package upcoming

import (
	"fmt"
	"io"
	"time"

	jsonout "github.com/sufield/stave/internal/adapters/output/json"
	textout "github.com/sufield/stave/internal/adapters/output/text"
	appupcoming "github.com/sufield/stave/internal/app/prune/upcoming"
	"github.com/sufield/stave/internal/cli/ui"
)

// renderOutput dispatches the UpcomingReport to the correct format adapter.
func renderOutput(w io.Writer, format ui.OutputFormat, out appupcoming.UpcomingReport, dueSoonThreshold time.Duration) error {
	if format.IsJSON() {
		return jsonout.WriteUpcomingJSON(w, out)
	}

	report := textout.RenderUpcomingMarkdown(
		toAdapterItems(out.Items),
		toAdapterSummary(out.UpcomingSummary),
		textout.UpcomingRenderOptions{
			Now:              out.GeneratedAt,
			DueSoonThreshold: dueSoonThreshold,
		},
	)
	if _, err := io.WriteString(w, report); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}

func toAdapterItems(items []appupcoming.UpcomingSnapshot) []textout.UpcomingItem {
	out := make([]textout.UpcomingItem, len(items))
	for i, item := range items {
		out[i] = textout.UpcomingItem{
			DueAt:          item.DueAt,
			Status:         string(item.Status),
			ControlID:      item.ControlID,
			AssetID:        item.AssetID,
			AssetType:      item.AssetType,
			FirstUnsafeAt:  item.FirstUnsafeAt,
			LastSeenUnsafe: item.LastSeenUnsafe,
			Threshold:      item.Threshold,
			Remaining:      item.Remaining,
		}
	}
	return out
}

func toAdapterSummary(s appupcoming.UpcomingSummary) textout.UpcomingSummary {
	return textout.UpcomingSummary{
		Overdue: s.Overdue,
		DueNow:  s.DueNow,
		DueSoon: s.DueSoon,
		Later:   s.Later,
		Total:   s.Total,
	}
}
