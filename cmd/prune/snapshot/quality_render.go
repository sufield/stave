package snapshot

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
)

func writeQualityOutput(format ui.OutputFormat, report qualityReport, quiet bool) error {
	if format.IsJSON() {
		if err := writeJSON(os.Stdout, report); err != nil {
			return fmt.Errorf("write quality report: %w", err)
		}
		return nil
	}
	if !quiet {
		renderQualityText(report)
	}
	return nil
}

func renderQualityText(report qualityReport) {
	out := os.Stdout
	summary := report.Summary
	status := "PASS"
	if !report.Pass {
		status = "FAIL"
	}
	fmt.Fprintf(out, "Snapshot quality: %s\n", status)
	fmt.Fprintf(out, "Snapshots: %d\n", summary.Snapshots)
	if !summary.OldestCapturedAt.IsZero() {
		fmt.Fprintf(out, "Oldest: %s\n", summary.OldestCapturedAt.Format(time.RFC3339))
	}
	if !summary.LatestCapturedAt.IsZero() {
		fmt.Fprintf(out, "Latest: %s\n", summary.LatestCapturedAt.Format(time.RFC3339))
	}
	if summary.MaxGap != "" {
		fmt.Fprintf(out, "Max gap: %s\n", summary.MaxGap)
	}
	if len(report.Issues) == 0 {
		fmt.Fprintln(out, "No quality issues detected.")
		return
	}
	fmt.Fprintln(out, "Issues:")
	for _, issue := range report.Issues {
		fmt.Fprintf(out, "- [%s] %s: %s\n", strings.ToUpper(issue.Severity), issue.Code, issue.Message)
	}
}
