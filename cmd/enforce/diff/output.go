package diff

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func writeOutput(cmd *cobra.Command, w io.Writer, format ui.OutputFormat, out asset.ObservationDelta) error {
	if cmdutil.QuietEnabled(cmd) {
		return nil
	}
	if format.IsJSON() {
		return writeJSON(w, out)
	}
	return writeText(w, out)
}

func writeJSON(w io.Writer, out asset.ObservationDelta) error {
	return jsonutil.WriteIndented(w, out)
}

func writeText(w io.Writer, out asset.ObservationDelta) error {
	if _, err := fmt.Fprintf(w, "Observation delta: %s -> %s\n", out.FromCaptured.Format(time.RFC3339), out.ToCaptured.Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Summary: added=%d removed=%d modified=%d total=%d\n\n",
		out.Summary.Added(), out.Summary.Removed(), out.Summary.Modified(), out.Summary.Total()); err != nil {
		return err
	}
	if len(out.Changes) == 0 {
		_, err := fmt.Fprintln(w, "No asset changes detected.")
		return err
	}
	for _, c := range out.Changes {
		if _, err := fmt.Fprintf(w, "- %s [%s]\n", c.AssetID, c.ChangeType); err != nil {
			return err
		}
		for _, p := range c.PropertyChanges {
			if _, err := fmt.Fprintf(w, "  * %s: %v -> %v\n", p.Path, p.From, p.To); err != nil {
				return err
			}
		}
	}
	return nil
}
