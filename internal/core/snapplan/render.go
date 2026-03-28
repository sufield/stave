package snapplan

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// humanTime is easier to scan in CLI output than RFC3339.
const humanTime = "2006-01-02 15:04:05"

// RenderPlanText writes a human-readable snapshot plan report to w.
func RenderPlanText(w io.Writer, plan *PlanOutput) error {
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

	modeHint := ""
	if plan.Mode == ModePreview {
		modeHint = " (use --apply --force to execute)"
	}
	ew.printf("Mode:      %s%s\n", plan.Mode, modeHint)

	if plan.ArchiveDir != "" {
		ew.printf("Archive:   %s\n", plan.ArchiveDir)
	}
}

func writeTiers(ew *errWriter, plan *PlanOutput) {
	if plan.TotalFiles == 0 {
		ew.println("\nNo snapshots discovered.")
		return
	}

	for _, summary := range plan.TierSummaries {
		ew.printf("\nTier: %s (older_than: %s, keep_min: %d)\n",
			summary.Tier, summary.OlderThan, summary.KeepMin)

		tw := tabwriter.NewWriter(ew.w, 0, 0, 2, ' ', 0)

		for _, f := range plan.Files {
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
	actionVerb := "processed"
	switch plan.Mode {
	case ModeArchive:
		actionVerb = "archived"
	case ModePrune:
		actionVerb = "pruned"
	}

	keepCount := 0
	for _, ts := range plan.TierSummaries {
		keepCount += ts.KeepCount
	}

	ew.println("\nSummary:")
	ew.printf("  Total Files:   %d\n", plan.TotalFiles)
	ew.printf("  Keep:          %d\n", keepCount)
	ew.printf("  To %-11s %d\n", actionVerb+":", plan.TotalActions)
}

// errWriter is a sticky-error helper for multi-line writing.
type errWriter struct {
	w   io.Writer
	err error
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
