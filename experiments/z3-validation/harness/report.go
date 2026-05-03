package harness

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// PrintSummary writes a one-screen text summary of the report to
// w. Used by the Makefile targets so the operator can see the
// pass/fail / agreement-rate / disagreement-counts at a glance
// without parsing the JSON.
func PrintSummary(w io.Writer, report *AgreementReport) {
	fmt.Fprintf(w, "service:        %s\n", report.Service)
	fmt.Fprintf(w, "fixtures:       %d\n", report.FixtureCount)
	fmt.Fprintf(w, "skipped:        %d\n", len(report.SkippedFixtures))
	fmt.Fprintf(w, "comparisons:    %d\n", report.TotalChecks)
	fmt.Fprintf(w, "agreements:     %d (%.1f%%)\n", report.Agreements, report.AgreementRate*100)
	fmt.Fprintf(w, "z3_only:        %d (potential CEL coverage gaps)\n", report.Z3Only)
	fmt.Fprintf(w, "cel_only:       %d (potential Z3 model bugs)\n", report.CELOnly)
	fmt.Fprintf(w, "collapse:       %s\n", report.CollapseRatio)
	if len(report.ModelCoverage.NotModeled) > 0 {
		fmt.Fprintln(w, "not modeled:")
		for _, item := range report.ModelCoverage.NotModeled {
			fmt.Fprintf(w, "  - %s\n", item)
		}
	}
}

// LoadReport loads a report from a previously-written summary.json.
// Used by the cross-service overall-report aggregator.
func LoadReport(path string) (*AgreementReport, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied to the report tool
	if err != nil {
		return nil, err
	}
	var report AgreementReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &report, nil
}
