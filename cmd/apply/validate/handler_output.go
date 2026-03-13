package validate

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appservice "github.com/sufield/stave/internal/app/service"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
)

// Reporter handles the formatting and writing of validation results.
type Reporter struct {
	Writer   io.Writer
	Format   string // "text", "json", or path to template
	Strict   bool
	FixHints bool
	IsJSON   bool // Global CLI --json mode
}

// Write outputs the validation result based on reporter configuration.
func (r *Reporter) Write(result *appservice.ValidationResult, opts *options) error {
	// 1. Build the portable report DTO
	report := buildReport(result, r.FixHints, opts)

	// 2. Route to correct formatter
	switch {
	case r.Format == "json":
		return outjson.WriteValidation(r.Writer, report, r.IsJSON, result.Valid())
	case r.Format != "" && r.Format != "text":
		return ui.ExecuteTemplate(r.Writer, r.Format, report)
	default:
		return r.writeText(result, report)
	}
}

// ExitStatus determines if the validation should result in a CLI error.
func (r *Reporter) ExitStatus(result *appservice.ValidationResult) error {
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

func (r *Reporter) writeText(res *appservice.ValidationResult, report Report) error {
	diagnostics := diagnosticsOf(res)

	// Header
	if err := r.printHeader(res.Valid(), len(report.Errors), len(report.Warnings)); err != nil {
		return err
	}

	// Issues
	for _, issue := range diagnostics.Issues {
		r.printIssue(issue)
	}

	// Summary
	fmt.Fprintf(r.Writer, "---\nChecked: %d controls, %d snapshots, %d asset observations",
		res.Summary.ControlsLoaded,
		res.Summary.SnapshotsLoaded,
		res.Summary.AssetObservationsLoaded)

	if res.Summary.IdentityObservationsLoaded > 0 {
		fmt.Fprintf(r.Writer, ", %d identity observations", res.Summary.IdentityObservationsLoaded)
	}
	fmt.Fprintln(r.Writer)

	// Fix Hints
	if r.FixHints && len(report.FixHints) > 0 {
		fmt.Fprintln(r.Writer, "\nSuggested next commands:")
		for _, h := range report.FixHints {
			fmt.Fprintf(r.Writer, "  - %s\n", h)
		}
	}
	return nil
}

func (r *Reporter) printHeader(valid bool, eCount, wCount int) error {
	if valid && wCount == 0 {
		_, err := fmt.Fprintln(r.Writer, "Validation passed")
		return err
	}

	status := "passed"
	if !valid {
		status = "failed"
	}

	msg := fmt.Sprintf("Validation %s (%d error%s", status, eCount, plural(eCount))
	if wCount > 0 {
		msg += fmt.Sprintf(", %d warning%s", wCount, plural(wCount))
	}
	msg += ")\n"
	_, err := fmt.Fprint(r.Writer, msg)
	return err
}

func (r *Reporter) printIssue(issue diag.Issue) {
	level := "WARNING"
	if issue.Signal == diag.SignalError {
		level = "ERROR"
	}

	fmt.Fprintln(r.Writer, ui.SeverityLabel(level, string(issue.Code), r.Writer))

	for _, key := range issue.Evidence.Keys() {
		fmt.Fprintf(r.Writer, "  %s=%s\n", key, issue.Evidence.Sanitized(key))
	}
	if issue.Action != "" {
		fmt.Fprintf(r.Writer, "  Fix: %s\n", issue.Action)
	}
	if issue.Command != "" {
		fmt.Fprintf(r.Writer, "  Example: %s\n", issue.Command)
	}
	fmt.Fprintln(r.Writer)
}

// --- Data Models (DTOs) ---

// Report is a clean DTO that maps the internal service result to the external output format.
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

func buildReport(res *appservice.ValidationResult, includeHints bool, opts *options) Report {
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
		report.FixHints = collectHints(d, hintContext{
			ControlsDir:     opts.Controls,
			ObservationsDir: opts.Observations,
		})
	}
	return report
}

// --- Helpers ---

func diagnosticsOf(result *appservice.ValidationResult) *diag.Result {
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

// PackConfigIssues checks for unknown control pack names in the project config.
func PackConfigIssues() []diag.Issue {
	cfg, ok := projconfig.FindProjectConfig()
	if !ok || len(cfg.EnabledControlPacks) == 0 {
		return nil
	}
	known, err := packs.PackNames()
	if err != nil {
		return []diag.Issue{
			diag.New(diag.CodePackRegistryLoadFailed).
				Error().
				Action("Reinstall Stave binary or verify embedded registry integrity").
				WithSensitive("error", err.Error()).
				Build(),
		}
	}
	knownSet := map[string]bool{}
	for _, name := range known {
		knownSet[name] = true
	}
	issues := make([]diag.Issue, 0)
	for _, raw := range cfg.EnabledControlPacks {
		name := strings.TrimSpace(raw)
		if name == "" || knownSet[name] {
			continue
		}
		issues = append(issues, diag.New(diag.CodeUnknownControlPack).
			Error().
			Action(fmt.Sprintf("Use a configured pack name: %s", strings.Join(known, ", "))).
			With("pack", name).
			Build())
	}
	return issues
}
