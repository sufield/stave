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
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	writef("Observation delta: %s -> %s\n", out.FromCaptured.Format(time.RFC3339), out.ToCaptured.Format(time.RFC3339))
	writef("Summary: added=%d removed=%d modified=%d total=%d\n\n",
		out.Summary.Added(), out.Summary.Removed(), out.Summary.Modified(), out.Summary.Total())
	if err != nil {
		return err
	}
	if len(out.Changes) == 0 {
		writef("No asset changes detected.\n")
		return err
	}
	for _, c := range out.Changes {
		writef("- %s [%s]\n", c.AssetID, c.ChangeType)
		for _, p := range c.PropertyChanges {
			writef("  * %s: %v -> %v\n", p.Path, p.From, p.To)
		}
	}
	return err
}
