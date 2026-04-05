package diff

import (
	"bufio"
	"fmt"
	"io"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// writeOutput dispatches rendering of the delta based on format.
// Pass io.Discard as w to suppress output in quiet mode.
func writeOutput(w io.Writer, format appcontracts.OutputFormat, out asset.InfrastructureDrift) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, out)
	}
	return renderText(w, out)
}

// renderText generates a human-readable summary of asset changes.
func renderText(w io.Writer, out asset.InfrastructureDrift) error {
	bw := bufio.NewWriter(w)

	var firstErr error
	printf := func(format string, args ...any) {
		if firstErr != nil {
			return
		}
		_, firstErr = fmt.Fprintf(bw, format, args...)
	}

	printf("Observation delta: %s -> %s\n",
		out.StartTime.Format(time.RFC3339),
		out.EndTime.Format(time.RFC3339))
	printf("Summary: added=%d removed=%d modified=%d total=%d\n\n",
		out.Summary.Provisioned(), out.Summary.Decommissioned(), out.Summary.Reconfigured(), out.Summary.Total())
	if firstErr != nil {
		return firstErr
	}

	if len(out.Changes) == 0 {
		printf("No asset changes detected.\n")
		return firstErr
	}

	for _, c := range out.Changes {
		if firstErr != nil {
			break
		}
		printf("- %s [%s]\n", c.AssetID, c.Action)
		for _, p := range c.Drifts {
			printf("  * %s: %v -> %v\n", p.Attribute, p.OldValue, p.NewValue)
		}
	}
	if err := bw.Flush(); err != nil && firstErr == nil {
		return err
	}
	return firstErr
}
