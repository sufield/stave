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
	if quiet {
		return nil
	}
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, report)
	}
	return renderQualityText(w, report)
}

func renderQualityText(w io.Writer, report qualityReport) error {
	var err error
	printf := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	s := report.Summary
	status := "PASS"
	if !report.Pass {
		status = "FAIL"
	}
	printf("Snapshot quality: %s\n", status)
	printf("Snapshots:        %d\n", s.Snapshots)
	if !s.OldestCapturedAt.IsZero() {
		printf("Oldest:           %s\n", s.OldestCapturedAt.Format(time.RFC3339))
	}
	if !s.LatestCapturedAt.IsZero() {
		printf("Latest:           %s\n", s.LatestCapturedAt.Format(time.RFC3339))
	}
	if s.MaxGap != "" {
		printf("Max gap:          %s\n", s.MaxGap)
	}

	if len(report.Issues) == 0 {
		printf("\nNo quality issues detected.\n")
		return err
	}

	printf("\nIssues:\n")
	for _, issue := range report.Issues {
		severity := strings.ToUpper(string(issue.Severity))
		label := ui.SeverityLabel(string(issue.Severity), severity, w)
		printf("- [%s] %s: %s\n", label, issue.Code, issue.Message)
	}

	return err
}
