package snapplan

import (
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
)

// humanTime is easier to scan in CLI output than RFC3339.
const humanTime = "2006-01-02 15:04:05"

// RenderPlanText writes a human-readable snapshot plan report to w.
// Returns an error when plan is nil so a caller that forgot to populate
// the plan slot fails loud here rather than panicking inside the
// downstream writers when they dereference plan.GeneratedAt / plan.Files.
func RenderPlanText(w io.Writer, plan *PlanOutput) error {
	if plan == nil {
		return errors.New("snapplan.RenderPlanText: plan is nil")
	}
	ew := &errWriter{w: w}

	writeHeader(ew, plan)
	writeTiers(ew, plan)
	writeSummary(ew, plan)

	return ew.err
}

func writeHeader(ew *errWriter, plan *PlanOutput) {
	ew.println("Snapshot Retention Plan")
	ew.println("=======================")
	ew.printf("Generated: %s\n", plan.GeneratedAt.Format(humanTime))
	ew.printf("Root:      %s\n", plan.ObservationsRoot)

	ew.printf("Mode:      %s (read-only — pass plan output to an external tool to act on it)\n", plan.Mode)
}

func writeTiers(ew *errWriter, plan *PlanOutput) {
	if plan.TotalFiles == 0 {
		ew.println("\nNo snapshots discovered.")
		return
	}

	for _, summary := range plan.TierSummaries {
		ew.printf("\nTier: %s (older_than: %s, keep_min: %d)\n",
			summary.Tier, summary.OlderThan, summary.KeepMin)

		// Wrap ew (not ew.w) so per-row Fprintf failures route
		// through the sticky-error gate. The earlier shape passed
		// the underlying writer, so a broken pipe inside the
		// tabwriter loop reached fmt.Fprintf, which discarded the
		// error — `ew.err` only saw the eventual Flush failure,
		// hiding which row first failed and producing truncated
		// tab-aligned output that looked correct in the
		// `ew.err == nil` branch.
		tw := tabwriter.NewWriter(ew, 0, 0, 2, ' ', 0)

		for i := range plan.Files {
			f := &plan.Files[i]
			if f.Tier != summary.Tier {
				continue
			}
			fmt.Fprintf(tw, "  %s\t%s\tcaptured: %s\t%s\n",
				f.Action,
				f.RelPath,
				f.CapturedAt.Format(humanTime),
				f.Reason,
			)
		}

		if err := tw.Flush(); err != nil && ew.err == nil {
			ew.err = err
		}
	}
}

func writeSummary(ew *errWriter, plan *PlanOutput) {
	// "eligible" rather than "pruned" / "archived": Stave never
	// executes the action, so the past-tense verbs that the previous
	// shape used (driven by ModePrune / ModeArchive) misrepresented
	// the read-only mode.
	actionVerb := "eligible for action"

	keepCount := 0
	for _, ts := range plan.TierSummaries {
		keepCount += ts.KeepCount
	}

	ew.println("\nSummary:")
	ew.printf("  Total Files:   %d\n", plan.TotalFiles)
	ew.printf("  Keep:          %d\n", keepCount)
	ew.printf("  To %-11s %d\n", actionVerb+":", plan.TotalActions)
}

// errWriter is a sticky-error helper for multi-line writing. It
// implements io.Writer so callers that need to hand a downstream
// writer (e.g. tabwriter.NewWriter) the same gated stream can do so
// without bypassing the sticky-error contract.
type errWriter struct {
	w   io.Writer
	err error
}

// Write satisfies io.Writer. Once err is set every subsequent write
// is a no-op, so a tabwriter / json.Encoder / any other consumer
// that loops over Write calls automatically short-circuits on the
// first failure.
func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.err != nil {
		return 0, ew.err
	}
	n, err := ew.w.Write(p)
	if err != nil {
		ew.err = err
	}
	return n, err
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func (ew *errWriter) println(args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, args...)
}
