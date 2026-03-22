package validate

import (
	"fmt"
	"io"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// Reporter handles the formatting and writing of validation results.
type Reporter struct {
	Writer     io.Writer
	Format     string // "text", "json", or path to template
	Strict     bool
	FixHints   bool
	GlobalJSON bool // Global CLI --json mode (affects JSON envelope)
}

// Write outputs the validation result based on reporter configuration.
// Returns an error if result is nil.
func (r *Reporter) Write(result *appvalidation.ValidationResult, hc hintContext) error {
	if result == nil {
		return fmt.Errorf("validation result is nil")
	}

	report := buildReport(result, r.FixHints, hc)

	switch {
	case r.Format == "json":
		return outjson.WriteValidation(r.Writer, report, r.GlobalJSON, result.Valid())
	case r.Format != "" && r.Format != "text":
		return ui.ExecuteTemplate(r.Writer, r.Format, report)
	default:
		return r.writeText(result, report)
	}
}

// ExitStatus determines if the validation should result in a CLI error.
// Returns an error if result is nil.
func (r *Reporter) ExitStatus(result *appvalidation.ValidationResult) error {
	if result == nil {
		return fmt.Errorf("validation result is nil")
	}
	if !result.Valid() {
		return ui.ErrValidationFailed
	}
	if result.HasWarnings() && r.Strict {
		return ui.ErrValidationFailed
	}
	if result.HasWarnings() {
		return ui.ErrValidationWarnings
	}
	return nil
}

// --- Internal Presentation Logic ---

func (r *Reporter) writeText(res *appvalidation.ValidationResult, report Report) error {
	diagnostics := diagnosticsOf(res)

	if err := printHeader(r.Writer, res.Valid(), len(report.Errors), len(report.Warnings)); err != nil {
		return err
	}

	for _, issue := range diagnostics.Issues {
		if err := printIssue(r.Writer, issue); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(r.Writer, "---\nChecked: %d controls, %d snapshots, %d asset observations",
		res.Summary.ControlsLoaded,
		res.Summary.SnapshotsLoaded,
		res.Summary.AssetObservationsLoaded); err != nil {
		return err
	}

	if res.Summary.IdentityObservationsLoaded > 0 {
		if _, err := fmt.Fprintf(r.Writer, ", %d identity observations", res.Summary.IdentityObservationsLoaded); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(r.Writer); err != nil {
		return err
	}

	if r.FixHints && len(report.FixHints) > 0 {
		if _, err := fmt.Fprintln(r.Writer, "\nSuggested next commands:"); err != nil {
			return err
		}
		for _, h := range report.FixHints {
			if _, err := fmt.Fprintf(r.Writer, "  - %s\n", h); err != nil {
				return err
			}
		}
	}
	return nil
}

func printHeader(w io.Writer, valid bool, eCount, wCount int) error {
	if valid && wCount == 0 {
		_, err := fmt.Fprintln(w, "Validation passed")
		return err
	}

	status := "passed"
	if !valid {
		status = "failed"
	}

	if wCount > 0 {
		_, err := fmt.Fprintf(w, "Validation %s (%d error%s, %d warning%s)\n",
			status, eCount, plural(eCount), wCount, plural(wCount))
		return err
	}
	_, err := fmt.Fprintf(w, "Validation %s (%d error%s)\n", status, eCount, plural(eCount))
	return err
}

func printIssue(w io.Writer, issue diag.Issue) error {
	level := "WARNING"
	if issue.Signal == diag.SignalError {
		level = "ERROR"
	}

	if _, err := fmt.Fprintln(w, ui.SeverityLabel(level, string(issue.Code), w)); err != nil {
		return err
	}

	for _, key := range issue.Evidence.Keys() {
		if _, err := fmt.Fprintf(w, "  %s=%s\n", key, issue.Evidence.Sanitized(key)); err != nil {
			return err
		}
	}
	if issue.Action != "" {
		if _, err := fmt.Fprintf(w, "  Fix: %s\n", issue.Action); err != nil {
			return err
		}
	}
	if issue.Command != "" {
		if _, err := fmt.Fprintf(w, "  Example: %s\n", issue.Command); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

// --- Data Models (DTOs) ---

// Report is a clean DTO that maps the internal service result to the external
// output format. diag.Issue is the stable public contract for validation issues.
type Report struct {
	SchemaVersion kernel.Schema `json:"schema_version"`
	Valid         bool          `json:"valid"`
	Errors        []diag.Issue  `json:"errors,omitempty"`
	Warnings      []diag.Issue  `json:"warnings,omitempty"`
	FixHints      []string      `json:"fix_hints,omitempty"`
	Summary       ReportSummary `json:"summary"`
}

// ReportSummary is the summary section of the validation report.
type ReportSummary struct {
	ControlsChecked             int `json:"controls_checked"`
	SnapshotsChecked            int `json:"snapshots_checked"`
	AssetObservationsChecked    int `json:"asset_observations_checked"`
	IdentityObservationsChecked int `json:"identity_observations_checked"`
}

func buildReport(res *appvalidation.ValidationResult, includeHints bool, hc hintContext) Report {
	d := diagnosticsOf(res)
	report := Report{
		SchemaVersion: kernel.SchemaValidate,
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

func diagnosticsOf(result *appvalidation.ValidationResult) *diag.Result {
	if result == nil || result.Diagnostics == nil {
		return diag.NewResult()
	}
	return result.Diagnostics
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
