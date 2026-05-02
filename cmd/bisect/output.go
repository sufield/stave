package bisect

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	appbisect "github.com/sufield/stave/internal/app/bisect"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/util/jsonutil"
)

func writeOutput(stdout, stderr io.Writer, result appbisect.Result, format string, logger *slog.Logger) error {
	if format == "json" {
		return jsonutil.WriteIndented(stdout, result)
	}
	return writeText(stdout, stderr, result, logger)
}

func writeText(stdout, stderr io.Writer, result appbisect.Result, _ *slog.Logger) error {
	modeName := "BISECT"
	if result.IsScanMode() {
		modeName = "SCAN"
	}

	if !result.HasViolation() {
		fmt.Fprintf(stdout, "%s COMPLETE: No violation found across %d snapshots.\n\n", modeName, result.SnapshotsTotal)
		fmt.Fprintf(stdout, "Invariant: %s has never been violated in this snapshot archive.\n", result.ControlID)
		return nil
	}

	fmt.Fprintf(stdout, "%s COMPLETE: %d violation window(s) found in %d steps (%d snapshots searched).\n\n",
		modeName, len(result.Windows), result.AssessmentsRun, result.SnapshotsTotal)
	fmt.Fprintf(stdout, "Invariant: %s\n", result.ControlID)
	if result.ResourceARN != "" {
		fmt.Fprintf(stdout, "Resource:  %s\n", result.ResourceARN)
	}
	fmt.Fprintln(stdout)

	for i, w := range result.Windows {
		if len(result.Windows) > 1 {
			label := ""
			if i == 0 {
				label = " (earliest)"
			}
			if w.IsOngoing {
				label = " (current)"
			}
			fmt.Fprintf(stdout, "Window %d%s:\n", i+1, label)
		}

		if w.EntryBefore.IsZero() {
			fmt.Fprintf(stdout, "  Violation predates the archive (present in earliest snapshot)\n")
			fmt.Fprintf(stdout, "  First observed: %s\n", w.EntryAfter.Format("2006-01-02T15:04:05Z"))
		} else {
			fmt.Fprintf(stdout, "  The change occurred between %s and %s.\n",
				w.EntryBefore.Format("2006-01-02T15:04:05Z"),
				w.EntryAfter.Format("2006-01-02T15:04:05Z"))
		}

		if w.IsOngoing {
			fmt.Fprintf(stdout, "  Status: ongoing (not yet remediated)\n")
		} else {
			fmt.Fprintf(stdout, "  Remediated between %s and %s.\n",
				w.ExitBefore.Format("2006-01-02T15:04:05Z"),
				w.ExitAfter.Format("2006-01-02T15:04:05Z"))
		}
		fmt.Fprintln(stdout)
	}

	if result.Delta != nil && len(result.Delta.Changes) > 0 {
		fmt.Fprintln(stdout, "State delta (between the two snapshots on either side of the transition):")
		fmt.Fprintln(stdout)
		for _, change := range result.Delta.Changes {
			for _, d := range change.Drifts {
				fmt.Fprintf(stdout, "  %-40s %v  →  %v\n", d.Attribute+":", d.OldValue, d.NewValue)
			}
		}
		fmt.Fprintln(stdout)
	}

	if !result.IsMonotonic && result.IsBisectMode() {
		fmt.Fprintln(stderr, "WARNING: Multiple violation windows detected in this snapshot range.")
		fmt.Fprintln(stderr, "         --mode bisect found the start of the current window only.")
		fmt.Fprintln(stderr, "         Run with --mode scan to find the earliest occurrence.")
		fmt.Fprintln(stderr)
	}

	if result.IsScanMode() && len(result.Windows) > 1 {
		fmt.Fprintf(stdout, "Patient Zero (earliest ever occurrence): Window 1\n")
	}

	fmt.Fprintln(stdout, strings.Repeat("-", 60))
	fmt.Fprintln(stdout, "Stave operates on snapshots. It cannot attribute changes to")
	fmt.Fprintln(stdout, "specific events within a window. To narrow the window, collect")
	fmt.Fprintln(stdout, "snapshots at higher frequency for this resource.")

	return ui.ErrViolationsFound
}
