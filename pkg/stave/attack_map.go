package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	appcoverage "github.com/sufield/stave/internal/app/coverage"
	"github.com/sufield/stave/internal/core/report"
)

// MapAttackCoverage builds a MITRE ATT&CK tactic coverage map from the
// control catalog in controlsDir, optionally overlaying current posture
// from an assessment (out.v0.1 JSON, nil to skip), and renders it in the
// requested format ("table"/"", "json", "navigator", or "markdown").
// minControls is the thin-coverage threshold. Loader and parse failures
// stay plain (exit 4). It is the library entry point behind `stave map`.
func MapAttackCoverage(ctx context.Context, controlsDir string, minControls int, assessmentData []byte, format string) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return nil, err
	}

	input := appcoverage.BuildInput{
		Controls:    controls,
		MinControls: minControls,
	}

	// Optional posture overlay.
	if len(assessmentData) > 0 {
		var assessment report.Assessment
		if jsonErr := json.Unmarshal(assessmentData, &assessment); jsonErr != nil {
			return nil, fmt.Errorf("parse assessment: %w", jsonErr)
		}
		input.Findings = assessment.Findings
	}

	return renderCoverageMap(appcoverage.Build(input), format)
}

// renderCoverageMap renders the coverage report in the requested format.
// Split out so the rendering can be unit-tested without loading controls.
func renderCoverageMap(coverageReport *appcoverage.CoverageReport, format string) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case "json":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(coverageReport); err != nil {
			return nil, fmt.Errorf("encode coverage map: %w", err)
		}
	case "navigator":
		layer := appcoverage.NavigatorLayer(coverageReport)
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(layer); err != nil {
			return nil, fmt.Errorf("encode navigator layer: %w", err)
		}
	case "markdown":
		writeMapMarkdown(&buf, coverageReport)
	case "table", "":
		writeMapTable(&buf, coverageReport)
	default:
		return nil, fmt.Errorf("unsupported format %q (expected: table | json | navigator | markdown)", format)
	}
	return buf.Bytes(), nil
}

func writeMapTable(w io.Writer, r *appcoverage.CoverageReport) {
	fmt.Fprintf(w, "MITRE ATT&CK COVERAGE MAP\n")
	fmt.Fprintf(w, "Controls: %d analyzed, %d annotated, %d unannotated\n\n",
		r.ControlsAnalyzed, r.ControlsAnnotated, r.ControlsUnannotated)

	// Gaps first.
	hasGaps := false
	for i := range r.Tactics {
		if r.Tactics[i].IsGap() {
			if !hasGaps {
				fmt.Fprintln(w, "COVERAGE GAPS")
				fmt.Fprintln(w, strings.Repeat("-", 70))
				hasGaps = true
			}
			tc := &r.Tactics[i]
			fmt.Fprintf(w, "  %-22s %-7s %3d controls  %s\n",
				tc.TacticName, tc.TacticID, tc.ControlCount, tc.DisplayStatus())
		}
	}
	if hasGaps {
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "FULL TACTIC COVERAGE")
	fmt.Fprintln(w, strings.Repeat("-", 70))
	for i := range r.Tactics {
		tc := &r.Tactics[i]
		passingStr := "—"
		if tc.PassingCount != nil {
			passingStr = fmt.Sprintf("%d/%d", *tc.PassingCount, tc.ControlCount)
		}
		fmt.Fprintf(w, "  %-22s %-7s %3d controls  %s\n",
			tc.TacticName, tc.TacticID, tc.ControlCount, passingStr)
	}

	fmt.Fprintf(w, "\nSummary: %d/%d tactics covered, %d thin, %d gaps\n",
		r.Summary.TacticsCovered, r.Summary.TacticsTotal, r.Summary.TacticsThin, r.Summary.TacticsNoCoverage)
}

func writeMapMarkdown(w io.Writer, r *appcoverage.CoverageReport) {
	fmt.Fprintln(w, "# MITRE ATT&CK Coverage Report")
	fmt.Fprintf(w, "Controls: %d | Annotated: %d\n\n", r.ControlsAnalyzed, r.ControlsAnnotated)

	fmt.Fprintln(w, "| Tactic | ID | Controls | Status |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for i := range r.Tactics {
		tc := &r.Tactics[i]
		fmt.Fprintf(w, "| %s | %s | %d | %s |\n",
			tc.TacticName, tc.TacticID, tc.ControlCount, tc.Status)
	}
}
