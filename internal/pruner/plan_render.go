package pruner

import (
	"fmt"
	"io"
	"time"
)

// RenderSnapshotPlanText writes a human-readable snapshot plan report.
func RenderSnapshotPlanText(w io.Writer, plan SnapshotPlanOutput) error {
	ew := &errWriter{w: w}
	writeSnapshotPlanHeader(ew, plan)
	writeSnapshotPlanTierSections(ew, plan)
	writeSnapshotPlanSummary(ew, plan)
	return ew.err
}

func writeSnapshotPlanHeader(ew *errWriter, plan SnapshotPlanOutput) {
	ew.println("Snapshot Retention Plan")
	ew.println("=======================")
	ew.printf("Generated: %s\n", plan.GeneratedAt.Format(time.RFC3339))
	ew.printf("Root:      %s\n", plan.ObservationsRoot)
	modeHint := ""
	if plan.Mode == ModePreview {
		modeHint = " (use --apply --force to execute)"
	}
	ew.printf("Mode:      %s%s\n", plan.Mode, modeHint)
}

func writeSnapshotPlanTierSections(ew *errWriter, plan SnapshotPlanOutput) {
	if plan.TotalFiles == 0 {
		ew.println("\nNo snapshots found.")
		return
	}

	// Pre-group files by tier to avoid O(tiers × files) scanning.
	byTier := make(map[string][]SnapshotPlanFile, len(plan.TierSummaries))
	for i := range plan.Files {
		f := &plan.Files[i]
		byTier[f.Tier] = append(byTier[f.Tier], *f)
	}

	for _, tierSummary := range plan.TierSummaries {
		writeSnapshotPlanTier(ew, tierSummary, byTier[tierSummary.Tier])
	}
}

func writeSnapshotPlanTier(ew *errWriter, tierSummary SnapshotPlanTierSummary, files []SnapshotPlanFile) {
	ew.printf("\nTier: %s (older_than=%s, keep_min=%d)\n", tierSummary.Tier, tierSummary.OlderThan, tierSummary.KeepMin)
	for _, file := range files {
		ew.printf("  %-8s %s  captured=%s  %s\n",
			file.Action, file.RelPath, file.CapturedAt.Format(time.RFC3339), file.Reason)
	}
}

func writeSnapshotPlanSummary(ew *errWriter, plan SnapshotPlanOutput) {
	actionWord := "prune"
	if plan.ArchiveDir != "" {
		actionWord = "archive"
	}
	// Derive keep count from tier summaries for cross-validation
	// rather than subtracting from totals.
	keepCount := 0
	for _, ts := range plan.TierSummaries {
		keepCount += ts.KeepCount
	}
	ew.printf("\nSummary: %d files, %d keep, %d %s\n",
		plan.TotalFiles, keepCount, plan.TotalActions, actionWord)
}

// errWriter is a sticky-error writer that absorbs fmt.Fprint errors,
// allowing rendering code to stay concise without per-call error checks.
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
