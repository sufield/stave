package upcoming

import (
	"fmt"
	"io"

	jsonout "github.com/sufield/stave/internal/adapters/output/json"
	textout "github.com/sufield/stave/internal/adapters/output/text"
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

// renderOutput dispatches the Output to the correct format adapter.
// Markdown is only generated when text format is requested.
func renderOutput(cfg UpcomingConfig, out Output) error {
	if cfg.Format.IsJSON() {
		return jsonout.WriteUpcomingJSON(cfg.Stdout, out)
	}

	report := textout.RenderUpcomingMarkdown(
		toAdapterItems(out.Items),
		toAdapterSummary(out.Summary),
		textout.UpcomingRenderOptions{
			Now:              cfg.Now,
			DueSoonThreshold: cfg.DueSoon,
		},
	)
	if _, err := io.WriteString(cfg.Stdout, report); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
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
