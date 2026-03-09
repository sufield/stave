package snapshot

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func writeQualityOutput(w io.Writer, format ui.OutputFormat, report qualityReport, quiet bool) error {
	if format.IsJSON() {
		if err := jsonutil.WriteIndented(w, report); err != nil {
			return fmt.Errorf("write quality report: %w", err)
		}
		return nil
	}
	if !quiet {
		renderQualityText(w, report)
	}
	return nil
}

func renderQualityText(w io.Writer, report qualityReport) {
	out := w
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
		fmt.Fprintf(out, "- [%s] %s: %s\n", strings.ToUpper(string(issue.Severity)), issue.Code, issue.Message)
	}
}
