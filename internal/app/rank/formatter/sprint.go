package formatter

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/app/sprintplanner"
)

// TextSprint renders a sprint plan as human-readable text.
type TextSprint struct{}

var _ SprintFormatter = (*TextSprint)(nil)

// Render writes the sprint plan to w. An empty plan still emits the
// header so an operator running the command sees the capacity that
// was budgeted.
func (TextSprint) Render(w io.Writer, r sprintplanner.SprintResult) error {
	if _, err := fmt.Fprintf(w, "SPRINT PLAN (%.0fh capacity)\n", r.Capacity); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("=", 60)); err != nil {
		return err
	}

	if len(r.Items) == 0 {
		_, err := fmt.Fprintln(w, "No items fit within the capacity budget.")
		return err
	}

	fmt.Fprintf(w, "\nINCLUDED (%d items, %.1fh total, %.1f risk reduction)\n",
		len(r.Items), r.TotalHours, r.RiskReduction)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintf(w, "  %-8s %-30s %-15s %6s %6s\n", "Severity", "Control", "Asset", "Hours", "ROI")

	for i := range r.Items {
		item := &r.Items[i]
		ctl := item.ControlID
		if len(ctl) > 30 {
			ctl = ctl[:27] + "..."
		}
		ast := item.AssetID
		if len(ast) > 15 {
			ast = ast[:12] + "..."
		}
		fmt.Fprintf(w, "  %-8s %-30s %-15s %6.1f %6.1f\n",
			strings.ToUpper(item.Severity), ctl, ast, item.EffortHours, item.ROI)
	}

	if len(r.LeftOut) > 0 {
		fmt.Fprintf(w, "\nLEFT OUT (%d items)\n", len(r.LeftOut))
		fmt.Fprintln(w, strings.Repeat("-", 60))
		for i := range r.LeftOut {
			item := &r.LeftOut[i]
			fmt.Fprintf(w, "  %-8s %s on %s (%.1fh)\n",
				strings.ToUpper(item.Severity), item.ControlID, item.AssetID, item.EffortHours)
		}
	}
	return nil
}
