package status

import (
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
)

// FormatText writes a human-readable status summary to w.
func FormatText(w io.Writer, result Result) error {
	s := result.State

	fmt.Fprintf(w, "Summary\n-------\n")
	fmt.Fprintf(w, "Project: %s\n", s.Root)

	if s.LastCommand != "" {
		fmt.Fprintf(w, "Last command: %s (%s)\n",
			s.LastCommand,
			s.LastCommandTime.Format(time.RFC3339))
	}

	fmt.Fprintln(w, "Artifacts:")
	fmt.Fprintf(w, "  - controls: %d\n", s.Controls.Count)
	fmt.Fprintf(w, "  - snapshots/raw: %d\n", s.RawSnapshots.Count)
	fmt.Fprintf(w, "  - observations: %d\n", s.Observations.Count)
	fmt.Fprintf(w, "  - output/evaluation.json: %v\n", s.HasEval)

	label := ui.SeverityLabel("info", fmt.Sprintf("Next: %s", result.NextCommand), w)
	fmt.Fprintf(w, "\n%s\n", label)
	return nil
}
