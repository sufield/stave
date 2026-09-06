package validatecmd

import (
	"errors"
	"fmt"
	"io"

	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
)

var errNilResult = errors.New("validation result is nil")

// Reporter handles the formatting and writing of validation results. The
// cli/ui-bound formatting (severity labels, template execution) is injected
// as Label/Template callbacks so this engine stays off the internal/cli/ui
// import graph (pkg/stave cannot import cli/ui).
type Reporter struct {
	Writer   io.Writer
	Format   string // "text", "json", or path to template
	Strict   bool
	FixHints bool
	Label    LabelFunc
	Template TemplateFunc
}

// Write outputs the validation result based on reporter configuration.
// Returns an error if result is nil.
func (r *Reporter) Write(result *appvalidation.Report, hc hintContext) error {
	if result == nil {
		return errNilResult
	}

	report := buildReport(result, r.FixHints, hc)

	renderer, err := NewRenderer(r.Format, r)
	if err != nil {
		return err
	}
	if err := renderer.Render(r.Writer, renderPayload{result: result, report: report}); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// ExitStatus determines if the validation should result in a CLI error.
// Returns an error if result is nil. The policy decision lives on
// Report.ExitError; this method is a thin wrapper that surfaces the
// nil-result error path.
func (r *Reporter) ExitStatus(result *appvalidation.Report) error {
	if result == nil {
		return errNilResult
	}
	if err := result.ExitError(r.Strict); err != nil {
		return fmt.Errorf("determine exit status: %w", err)
	}
	return nil
}

// --- Internal Presentation Logic ---

func (r *Reporter) writeText(res *appvalidation.Report, report Report) error {
	diagnostics := diagnosticsOf(res)

	if err := printHeader(r.Writer, res.Valid(), len(report.Errors), len(report.Warnings)); err != nil {
		return err
	}

	for _, issue := range diagnostics.Findings {
		if err := printIssue(r.Writer, issue, r.Label); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(r.Writer, "---\nChecked: %d controls, %d snapshots, %d asset observations",
		res.Summary.ControlsLoaded,
		res.Summary.SnapshotsLoaded,
		res.Summary.AssetObservationsLoaded); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	if res.Summary.IdentityObservationsLoaded > 0 {
		if _, err := fmt.Fprintf(r.Writer, ", %d identity observations", res.Summary.IdentityObservationsLoaded); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	if _, err := fmt.Fprintln(r.Writer); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	if r.FixHints && len(report.FixHints) > 0 {
		if _, err := fmt.Fprintln(r.Writer, "\nSuggested next commands:"); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		for _, h := range report.FixHints {
			if _, err := fmt.Fprintf(r.Writer, "  - %s\n", h); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
	}
	return nil
}

func printHeader(w io.Writer, valid bool, eCount, wCount int) error {
	if valid && wCount == 0 {
		if _, err := fmt.Fprintln(w, "Validation passed"); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}

	status := "passed"
	if !valid {
		status = "failed"
	}

	if wCount > 0 {
		if _, err := fmt.Fprintf(w, "Validation %s (%d error%s, %d warning%s)\n",
			status, eCount, plural(eCount), wCount, plural(wCount)); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "Validation %s (%d error%s)\n", status, eCount, plural(eCount)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func printIssue(w io.Writer, issue diag.Finding, label LabelFunc) error {
	if _, err := fmt.Fprintln(w, label(issue.SeverityLabel(), string(issue.RuleID), w)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	for _, key := range issue.Resource.Keys() {
		if _, err := fmt.Fprintf(w, "  %s=%s\n", key, issue.Resource.Sanitized(key)); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	if issue.Remediation != "" {
		if _, err := fmt.Fprintf(w, "  Fix: %s\n", issue.Remediation); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	if issue.FixCommand != "" {
		if _, err := fmt.Fprintf(w, "  Example: %s\n", issue.FixCommand); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// --- Data Models (DTOs) ---

// Report is a clean DTO that maps the internal service result to the external
// output format. diag.Finding is the stable public contract for validation issues.
type Report struct {
	SchemaVersion kernel.Schema  `json:"schema_version"`
	Valid         bool           `json:"valid"`
	Errors        []diag.Finding `json:"errors,omitempty"`
	Warnings      []diag.Finding `json:"warnings,omitempty"`
	FixHints      []string       `json:"fix_hints,omitempty"`
	Summary       ReportSummary  `json:"summary"`
}

// ReportSummary is the summary section of the validation report.
type ReportSummary struct {
	ControlsChecked             int `json:"controls_checked"`
	SnapshotsChecked            int `json:"snapshots_checked"`
	AssetObservationsChecked    int `json:"asset_observations_checked"`
	IdentityObservationsChecked int `json:"identity_observations_checked"`
}

func buildReport(res *appvalidation.Report, includeHints bool, hc hintContext) Report {
	d := diagnosticsOf(res)
	report := Report{
		SchemaVersion: kernel.SchemaLint,
		Valid:         res.Valid(),
		Errors:        d.Errors(),
		Warnings:      d.Warnings(),
		Summary: ReportSummary{
			ControlsChecked:             res.Summary.ControlsLoaded,
			SnapshotsChecked:            res.Summary.SnapshotsLoaded,
			AssetObservationsChecked:    res.Summary.AssetObservationsLoaded,
			IdentityObservationsChecked: res.Summary.IdentityObservationsLoaded,
		},
	}

	if includeHints {
		report.FixHints = collectHints(d, hc)
	}
	return report
}

// --- Helpers ---

func diagnosticsOf(result *appvalidation.Report) *diag.Assessment {
	if result == nil || result.Diagnostics == nil {
		return diag.NewAssessment()
	}
	return result.Diagnostics
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
