package snapshot

import (
	"fmt"
	"io"
	"time"
)

// RenderPlanText writes a human-readable snapshot plan report.
func RenderPlanText(w io.Writer, plan *PlanOutput) error {
	ew := &errWriter{w: w}
	writePlanHeader(ew, plan)
	writePlanTierSections(ew, plan)
	writePlanSummary(ew, plan)
	return ew.err
}

func writePlanHeader(ew *errWriter, plan *PlanOutput) {
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

func writePlanTierSections(ew *errWriter, plan *PlanOutput) {
	if plan.TotalFiles == 0 {
		ew.println("\nNo snapshots found.")
		return
	}

	byTier := make(map[string][]PlanFile, len(plan.TierSummaries))
	for i := range plan.Files {
		f := &plan.Files[i]
		byTier[f.Tier] = append(byTier[f.Tier], *f)
	}

	for _, tierSummary := range plan.TierSummaries {
		writePlanTier(ew, tierSummary, byTier[tierSummary.Tier])
	}
}

func writePlanTier(ew *errWriter, tierSummary PlanTierSummary, files []PlanFile) {
	ew.printf("\nTier: %s (older_than=%s, keep_min=%d)\n", tierSummary.Tier, tierSummary.OlderThan, tierSummary.KeepMin)
	for _, file := range files {
		ew.printf("  %-8s %s  captured=%s  %s\n",
			file.Action, file.RelPath, file.CapturedAt.Format(time.RFC3339), file.Reason)
	}
}

func writePlanSummary(ew *errWriter, plan *PlanOutput) {
	actionWord := "prune"
	if plan.ArchiveDir != "" {
		actionWord = "archive"
	}
	keepCount := 0
	for _, ts := range plan.TierSummaries {
		keepCount += ts.KeepCount
	}
	ew.printf("\nSummary: %d files, %d keep, %d %s\n",
		plan.TotalFiles, keepCount, plan.TotalActions, actionWord)
}

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
