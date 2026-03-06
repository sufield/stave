package validate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"

	appservice "github.com/sufield/stave/internal/app/service"
)

func writeFixHints(w io.Writer, issues []diag.Issue, opts *options) error {
	hints := collectFixHints(issues, opts)
	if len(hints) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nSuggested next commands:\n"); err != nil {
		return err
	}
	for _, h := range hints {
		if _, err := fmt.Fprintf(w, "  - %s\n", h); err != nil {
			return err
		}
	}
	return nil
}

func collectFixHints(issues []diag.Issue, opts *options) []string {
	return collectHints(
		&diag.Result{Issues: issues},
		hintContext{
			ControlsDir:     opts.ControlsDir,
			ObservationsDir: opts.ObservationsDir,
		},
	)
}

// ValidateSchemaVersion is the schema version for validate output.
const ValidateSchemaVersion = string(kernel.SchemaValidate)

// JSONValidationReport is the JSON output structure.
type JSONValidationReport struct {
	SchemaVersion string                `json:"schema_version"`
	Valid         bool                  `json:"valid"`
	Errors        []diag.Issue          `json:"errors,omitempty"`
	Warnings      []diag.Issue          `json:"warnings,omitempty"`
	FixHints      []string              `json:"fix_hints,omitempty"`
	Summary       JSONValidationSummary `json:"summary"`
}

// JSONValidationSummary is the JSON summary structure.
type JSONValidationSummary struct {
	ControlsChecked             int `json:"controls_checked"`
	SnapshotsChecked            int `json:"snapshots_checked"`
	AssetObservationsChecked int `json:"asset_observations_checked"`
	IdentityObservationsChecked int `json:"identity_observations_checked"`
}

// ValidationEnvelope wraps validation results in ok/data structure.
type ValidationEnvelope struct {
	OK   bool                 `json:"ok"`
	Data JSONValidationReport `json:"data"`
}

// outputAndExit writes the result and returns appropriate error for exit code.
// Returns write errors if output fails, otherwise returns validation status.
func outputAndExit(cmd *cobra.Command, w io.Writer, result *appservice.ValidationResult, jsonOutput bool) error {
	return outputAndExitWithOptions(cmd, w, result, jsonOutput, validateOpts)
}

func outputAndExitWithOptions(cmd *cobra.Command, w io.Writer, result *appservice.ValidationResult, jsonOutput bool, opts *options) error {
	if opts.Template != "" {
		return outputTemplateAndExit(w, result, opts)
	}
	if err := writeValidationOutput(cmd, w, result, jsonOutput, opts); err != nil {
		return err
	}
	return validationExitError(result, opts)
}

func outputTemplateAndExit(w io.Writer, result *appservice.ValidationResult, opts *options) error {
	report := buildJSONValidationReport(result, opts)
	if err := ui.ExecuteTemplate(w, opts.Template, report); err != nil {
		return err
	}
	if !result.Valid() {
		return ui.ErrValidationFailed
	}
	if result.HasWarnings() && opts.StrictMode {
		return ui.ErrValidationFailed
	}
	return nil
}

func writeValidationOutput(cmd *cobra.Command, w io.Writer, result *appservice.ValidationResult, jsonOutput bool, opts *options) error {
	if jsonOutput {
		return writeValidationJSON(cmd, w, result, opts)
	}
	return writeValidationTextWithOptions(w, result, opts)
}

func validationExitError(result *appservice.ValidationResult, opts *options) error {
	if !result.Valid() {
		return ui.ErrValidationFailed
	}
	if !result.HasWarnings() {
		return nil
	}
	if opts.StrictMode {
		return ui.ErrValidationFailed
	}
	return ui.ErrValidationWarnings
}

func diagnosticsOf(result *appservice.ValidationResult) *diag.Result {
	if result == nil || result.Diagnostics == nil {
		return diag.NewResult()
	}
	return result.Diagnostics
}

// writeValidationText outputs human-readable validation results.
// Returns an error if writing to the output fails.
func writeValidationText(w io.Writer, result *appservice.ValidationResult) error {
	return writeValidationTextWithOptions(w, result, validateOpts)
}

func writeValidationTextWithOptions(w io.Writer, result *appservice.ValidationResult, opts *options) error {
	diagnostics := diagnosticsOf(result)
	counts := issueCounts{errors: len(diagnostics.Errors()), warnings: len(diagnostics.Warnings())}

	if err := writeValidationHeader(w, result.Valid(), counts); err != nil {
		return err
	}
	if err := writeValidationIssues(w, diagnostics.Issues); err != nil {
		return err
	}
	if err := writeValidationSummary(w, result.Summary); err != nil {
		return err
	}
	if opts.FixHints && len(diagnostics.Issues) > 0 {
		if err := writeFixHints(w, diagnostics.Issues, opts); err != nil {
			return err
		}
	}
	return writeValidationNextStep(w, result.Valid(), counts.warnings, opts)
}

type issueCounts struct {
	errors   int
	warnings int
}

func writeValidationHeader(w io.Writer, valid bool, counts issueCounts) error {
	switch {
	case valid && counts.warnings == 0:
		_, err := fmt.Fprintln(w, "Validation passed")
		return err
	case valid:
		_, err := fmt.Fprintf(w, "Validation passed (%d warning%s)\n", counts.warnings, plural(counts.warnings))
		return err
	default:
		return writeValidationFailedHeader(w, counts)
	}
}

func writeValidationFailedHeader(w io.Writer, counts issueCounts) error {
	if _, err := fmt.Fprintf(w, "Validation failed (%d error%s", counts.errors, plural(counts.errors)); err != nil {
		return err
	}
	if counts.warnings > 0 {
		if _, err := fmt.Fprintf(w, ", %d warning%s", counts.warnings, plural(counts.warnings)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, ")")
	return err
}

func writeValidationIssues(w io.Writer, issues []diag.Issue) error {
	for _, issue := range issues {
		if err := writeIssue(w, issue); err != nil {
			return err
		}
	}
	return nil
}

func writeValidationSummary(w io.Writer, summary appservice.ValidationSummary) error {
	if _, err := fmt.Fprintln(w, "---"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Checked: %d controls, %d snapshots, %d asset observations",
		summary.ControlsLoaded,
		summary.SnapshotsLoaded,
		summary.AssetObservationsLoaded); err != nil {
		return err
	}
	if summary.IdentityObservationsLoaded > 0 {
		if _, err := fmt.Fprintf(w, ", %d identity observations", summary.IdentityObservationsLoaded); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

func writeValidationNextStep(w io.Writer, valid bool, warningCount int, opts *options) error {
	if !valid || warningCount > 0 {
		return nil
	}
	_, err := fmt.Fprintf(w, "\nNext step:\n  stave apply --controls %s --observations %s\n",
		opts.ControlsDir, opts.ObservationsDir)
	return err
}

// writeIssue writes a single validation issue.
// Returns an error if writing to the output fails.
func writeIssue(w io.Writer, issue diag.Issue) error {
	level := "WARNING"
	if issue.Signal == diag.SignalError {
		level = "ERROR"
	}
	line := ui.SeverityLabel(level, issue.Code, w)
	if _, err := fmt.Fprintln(w, line); err != nil {
		return err
	}

	for _, key := range issue.Evidence.Keys() {
		value := issue.Evidence.Sanitized(key)
		if _, err := fmt.Fprintf(w, "  %s=%s\n", key, value); err != nil {
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

// buildJSONValidationReport constructs a JSONValidationReport from a ValidateResult.
func buildJSONValidationReport(result *appservice.ValidationResult, opts *options) JSONValidationReport {
	diagnostics := diagnosticsOf(result)
	report := JSONValidationReport{
		SchemaVersion: ValidateSchemaVersion,
		Valid:         result.Valid(),
		Summary: JSONValidationSummary{
			ControlsChecked:             result.Summary.ControlsLoaded,
			SnapshotsChecked:            result.Summary.SnapshotsLoaded,
			AssetObservationsChecked: result.Summary.AssetObservationsLoaded,
			IdentityObservationsChecked: result.Summary.IdentityObservationsLoaded,
		},
	}

	report.Errors = diagnostics.Errors()
	report.Warnings = diagnostics.Warnings()
	if opts.FixHints {
		report.FixHints = collectFixHints(diagnostics.Issues, opts)
	}
	return report
}

// writeValidationJSON outputs JSON validation results.
// Returns an error if encoding or writing fails.
// If global JSON mode is set, wraps output in {"ok": true, "data": ...}.
func writeValidationJSON(cmd *cobra.Command, w io.Writer, result *appservice.ValidationResult, opts *options) error {
	report := buildJSONValidationReport(result, opts)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	// Use envelope wrapper when global JSON mode is set
	if cmdutil.IsJSONMode(cmd) {
		envelope := ValidationEnvelope{OK: result.Valid(), Data: report}
		return enc.Encode(envelope)
	}
	return enc.Encode(report)
}

// plural returns "s" for plural forms when count is not 1.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// validateOutput returns the appropriate output writer based on quiet mode.
func validateOutput() io.Writer {
	return validateOutputWithOptions(validateOpts)
}

func validateOutputWithOptions(opts *options) io.Writer {
	if opts.QuietMode {
		return io.Discard
	}
	return os.Stdout
}

// PackConfigIssues checks for unknown control pack names in the project config.
func PackConfigIssues() []diag.Issue {
	cfg, ok := cmdutil.FindProjectConfig()
	if !ok || len(cfg.EnabledControlPacks) == 0 {
		return nil
	}
	known, err := packs.PackNames()
	if err != nil {
		return []diag.Issue{
			diag.New("PACK_REGISTRY_LOAD_FAILED").
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
		issues = append(issues, diag.New("UNKNOWN_CONTROL_PACK").
			Error().
			Action(fmt.Sprintf("Use a configured pack name: %s", strings.Join(known, ", "))).
			With("pack", name).
			Build())
	}
	return issues
}
