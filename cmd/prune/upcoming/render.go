package upcoming

import (
	"fmt"
	"io"
	"time"

	jsonout "github.com/sufield/stave/internal/adapters/output/json"
	textout "github.com/sufield/stave/internal/adapters/output/text"
	"github.com/sufield/stave/internal/cli/ui"
)

func buildOutput(cfg UpcomingConfig, summary Summary, items []Item) Output {
	return Output{
		GeneratedAt:  cfg.Now,
		ControlsDir:  cfg.ControlsDir,
		Observations: cfg.ObservationsDir,
		MaxUnsafe:    cfg.MaxUnsafeRaw,
		DueSoon:      cfg.DueSoonRaw,
		Summary:      summary,
		Items:        items,
	}
}

func writeOutput(format ui.OutputFormat, w io.Writer, report string, jsonOut Output) error {
	if format.IsJSON() {
		return jsonout.WriteUpcomingJSON(w, jsonOut)
	}
	if _, err := io.WriteString(w, report); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func renderSummaryMarkdown(summary Summary, dueSoonThreshold time.Duration) string {
	return textout.RenderUpcomingSummaryMarkdown(toAdapterSummary(summary), dueSoonThreshold)
}

func renderUpcomingMarkdown(items []Item, summary Summary, opts RenderOptions) string {
	return textout.RenderUpcomingMarkdown(toAdapterItems(items), toAdapterSummary(summary), textout.UpcomingRenderOptions{
		Now:              opts.Now,
		DueSoonThreshold: opts.DueSoonThreshold,
	})
}

func toAdapterItems(items []Item) []textout.UpcomingItem {
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

func toAdapterSummary(s Summary) textout.UpcomingSummary {
	return textout.UpcomingSummary{
		Overdue: s.Overdue,
		DueNow:  s.DueNow,
		DueSoon: s.DueSoon,
		Later:   s.Later,
		Total:   s.Total,
	}
}
