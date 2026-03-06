package pruner

import (
	"fmt"
	"io"
	"time"
)

// RenderSnapshotPlanText writes a human-readable snapshot plan report.
func RenderSnapshotPlanText(w io.Writer, plan SnapshotPlanOutput) error {
	if err := writeSnapshotPlanHeader(w, plan); err != nil {
		return err
	}
	if err := writeSnapshotPlanTierSections(w, plan); err != nil {
		return err
	}
	return writeSnapshotPlanSummary(w, plan)
}

func writeSnapshotPlanHeader(w io.Writer, plan SnapshotPlanOutput) error {
	if _, err := fmt.Fprintln(w, "Snapshot Retention Plan"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "======================="); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Generated: %s\n", plan.GeneratedAt.Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Root:      %s\n", plan.ObservationsRoot); err != nil {
		return err
	}
	modeHint := ""
	if plan.Mode == "PREVIEW" {
		modeHint = " (use --apply --force to execute)"
	}
	_, err := fmt.Fprintf(w, "Mode:      %s%s\n", plan.Mode, modeHint)
	return err
}

func writeSnapshotPlanTierSections(w io.Writer, plan SnapshotPlanOutput) error {
	for _, tierSummary := range plan.TierSummaries {
		if err := writeSnapshotPlanTier(w, tierSummary, plan.Files); err != nil {
			return err
		}
	}
	return nil
}

func writeSnapshotPlanTier(w io.Writer, tierSummary SnapshotPlanTierSummary, files []SnapshotPlanFile) error {
	if _, err := fmt.Fprintf(w, "\nTier: %s (older_than=%s, keep_min=%d)\n", tierSummary.Tier, tierSummary.OlderThan, tierSummary.KeepMin); err != nil {
		return err
	}
	for _, file := range files {
		if file.Tier != tierSummary.Tier {
			continue
		}
		if _, err := fmt.Fprintf(w, "  %-8s %s  captured=%s  %s\n",
			file.Action, file.RelPath, file.CapturedAt.Format(time.RFC3339), file.Reason); err != nil {
			return err
		}
	}
	return nil
}

func writeSnapshotPlanSummary(w io.Writer, plan SnapshotPlanOutput) error {
	actionWord := "prune"
	if plan.ArchiveDir != "" {
		actionWord = "archive"
	}
	keepCount := plan.TotalFiles - plan.TotalActions
	_, err := fmt.Fprintf(w, "\nSummary: %d files, %d keep, %d %s\n",
		plan.TotalFiles, keepCount, plan.TotalActions, actionWord)
	return err
}
