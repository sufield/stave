package upcoming

import (
	"fmt"
	"io"
	"time"

	jsonout "github.com/sufield/stave/internal/adapters/output/json"
	textout "github.com/sufield/stave/internal/adapters/output/text"
	"github.com/sufield/stave/internal/cli/ui"
)

func buildUpcomingOutput(opts upcomingRunOptions, summary UpcomingSummary, items []UpcomingItem) UpcomingOutput {
	return UpcomingOutput{
		GeneratedAt:  opts.Now,
		ControlsDir:  opts.ControlsDir,
		Observations: opts.ObservationsDir,
		MaxUnsafe:    opts.MaxUnsafeRaw,
		DueSoon:      opts.DueSoonRaw,
		Summary:      summary,
		Items:        items,
	}
}

func writeUpcomingOutput(format ui.OutputFormat, w io.Writer, report string, jsonOut UpcomingOutput) error {
	if format.IsJSON() {
		return jsonout.WriteUpcomingJSON(w, jsonOut)
	}
	if _, err := io.WriteString(w, report); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func renderUpcomingSummaryMarkdown(summary UpcomingSummary, dueSoonThreshold time.Duration) string {
	return textout.RenderUpcomingSummaryMarkdown(toAdapterSummary(summary), dueSoonThreshold)
}

func renderUpcomingMarkdown(items []UpcomingItem, summary UpcomingSummary, opts UpcomingRenderOptions) string {
	return textout.RenderUpcomingMarkdown(toAdapterItems(items), toAdapterSummary(summary), textout.UpcomingRenderOptions{
		Now:              opts.Now,
		DueSoonThreshold: opts.DueSoonThreshold,
	})
}

func toAdapterItems(items []UpcomingItem) []textout.UpcomingItem {
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

func toAdapterSummary(s UpcomingSummary) textout.UpcomingSummary {
	return textout.UpcomingSummary{
		Overdue: s.Overdue,
		DueNow:  s.DueNow,
		DueSoon: s.DueSoon,
		Later:   s.Later,
		Total:   s.Total,
	}
}
