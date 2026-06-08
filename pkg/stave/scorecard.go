package stave

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/sufield/stave/internal/adapters/observations"
	appsc "github.com/sufield/stave/internal/app/scorecard"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

var defaultScorecardFrameworks = []string{
	"hipaa", "nist_800_53_r5", "fedramp_moderate", "soc2",
	"pci_dss_v4.0", "cis_aws_v3.0", "iso_27001_2022",
}

// RenderScorecard computes the multi-framework compliance scorecard from a
// `stave apply` assessment (JSON with findings) and renders it in the
// requested format ("json", "markdown", or "table"/"text"/""). When
// profiles is empty the built-in framework set is used. Parse failures,
// raw-snapshot misuse, and unsupported formats wrap [ErrInvalidInput]. It
// is the library entry point behind `stave scorecard`.
func RenderScorecard(data []byte, profiles []string, format string) ([]byte, error) {
	// Try loading as assessment JSON first (has findings).
	var assessment struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &assessment); err != nil {
		// Detect the raw-bundle case first (operator pointed scorecard at
		// the wrong file) and surface a clear hint; otherwise the
		// unmarshal failure is the actual cause.
		if _, loadErr := observations.ParseBundle(data); loadErr == nil {
			return nil, fmt.Errorf("--snapshot must be stave apply JSON output (assessment), not a raw observation snapshot: %w", ErrInvalidInput)
		}
		return nil, fmt.Errorf("parse assessment: %w: %w", err, ErrInvalidInput)
	}
	if len(assessment.Findings) == 0 {
		// Zero findings is a legitimate input: every control passed.
		// Surface it as a debug log so operators running with -v can
		// confirm the scorecard ran against an actual assessment.
		slog.Debug("scorecard: assessment contained zero findings — treating as all-passing")
	}

	frameworks := profiles
	if len(frameworks) == 0 {
		frameworks = defaultScorecardFrameworks
	}

	report := appsc.Compute(assessment.Findings, frameworks)

	var buf bytes.Buffer
	switch format {
	case "json":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return nil, fmt.Errorf("render output: %w", err)
		}
	case "markdown":
		writeScorecardMarkdown(&buf, report)
	case "table", "text", "":
		writeScorecardTable(&buf, report)
	default:
		return nil, fmt.Errorf("unsupported format %q (expected: json | markdown | table): %w", format, ErrInvalidInput)
	}
	return buf.Bytes(), nil
}

func writeScorecardTable(w io.Writer, r *appsc.Report) {
	fmt.Fprintln(w, "COMPLIANCE SCORECARD")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-20s %10s %10s\n", "Framework", "Readiness", "Critical")
	fmt.Fprintf(w, "%-20s %10s %10s\n", strings.Repeat("-", 20), strings.Repeat("-", 10), strings.Repeat("-", 10))
	for i := range r.Frameworks {
		fw := &r.Frameworks[i]
		fmt.Fprintf(w, "%-20s %9.1f%% %10d\n", fw.Framework, fw.ReadinessPct, fw.CriticalFindings)
	}
}

func writeScorecardMarkdown(w io.Writer, r *appsc.Report) {
	fmt.Fprintln(w, "# Compliance Scorecard")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Framework | Readiness | Critical | Next Action |")
	fmt.Fprintln(w, "|-----------|-----------|----------|-------------|")
	for i := range r.Frameworks {
		fw := &r.Frameworks[i]
		fmt.Fprintf(w, "| %s | %.1f%% | %d | %s |\n",
			fw.Framework, fw.ReadinessPct, fw.CriticalFindings, fw.NextAction)
	}
}
