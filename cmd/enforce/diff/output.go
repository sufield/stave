package diff

import (
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
)

// writeOutput dispatches rendering of the delta based on format and quiet mode.
func writeOutput(w io.Writer, format ui.OutputFormat, quiet bool, out asset.ObservationDelta) error {
	if quiet {
		return nil
	}
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, out)
	}
	return renderText(w, out)
}

// renderText generates a human-readable summary of asset changes.
func renderText(w io.Writer, out asset.ObservationDelta) error {
	var firstErr error
	printf := func(format string, args ...any) {
		if firstErr != nil {
			return
		}
		_, firstErr = fmt.Fprintf(w, format, args...)
	}

	printf("Observation delta: %s -> %s\n",
		out.FromCaptured.Format(time.RFC3339),
		out.ToCaptured.Format(time.RFC3339))
	printf("Summary: added=%d removed=%d modified=%d total=%d\n\n",
		out.Summary.Added(), out.Summary.Removed(), out.Summary.Modified(), out.Summary.Total())
	if firstErr != nil {
		return firstErr
	}

	if len(out.Changes) == 0 {
		printf("No asset changes detected.\n")
		return firstErr
	}

	for _, c := range out.Changes {
		printf("- %s [%s]\n", c.AssetID, c.ChangeType)
		for _, p := range c.PropertyChanges {
			printf("  * %s: %v -> %v\n", p.Path, p.From, p.To)
		}
	}
	return firstErr
}
