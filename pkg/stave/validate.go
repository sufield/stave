package stave

import (
	"context"
	"errors"
	"fmt"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
)

// ValidateConfig controls what Validate checks.
type ValidateConfig struct {
	// SnapshotsDir is the observation snapshots directory (required).
	SnapshotsDir string

	// ControlsDir is the control definitions directory.
	// Empty means use the embedded builtin catalog.
	ControlsDir string
}

// ValidationSeverity classifies the diagnostic issue severity level.
type ValidationSeverity string

const (
	ValidationSeverityError   ValidationSeverity = "error"
	ValidationSeverityWarning ValidationSeverity = "warning"
)

// String returns the underlying string representation of the severity.
func (s ValidationSeverity) String() string {
	return string(s)
}

// IsError reports whether the severity is an error.
func (s ValidationSeverity) IsError() bool {
	return s == ValidationSeverityError
}

// IsWarning reports whether the severity is a warning.
func (s ValidationSeverity) IsWarning() bool {
	return s == ValidationSeverityWarning
}

// ValidationFinding is one diagnostic issue found during validation.
type ValidationFinding struct {
	// RuleID identifies the validation rule that fired.
	RuleID string

	// Severity is "error" or "warning".
	Severity ValidationSeverity

	// Message describes the issue.
	Message string

	// Remediation is a suggested fix.
	Remediation string
}

// IsError reports whether the finding is error-level.
func (f ValidationFinding) IsError() bool {
	return f.Severity.IsError()
}

// IsWarning reports whether the finding is warning-level.
func (f ValidationFinding) IsWarning() bool {
	return f.Severity.IsWarning()
}

// ValidationFindings represents a domain collection of ValidationFinding items with query methods.
type ValidationFindings []ValidationFinding

// Len returns the number of findings in the collection.
func (vf ValidationFindings) Len() int {
	return len(vf)
}

// IsEmpty reports whether the collection contains no findings.
func (vf ValidationFindings) IsEmpty() bool {
	return len(vf) == 0
}

// Errors returns only the error-level findings.
func (vf ValidationFindings) Errors() ValidationFindings {
	if len(vf) == 0 {
		return nil
	}
	var out ValidationFindings
	for _, f := range vf {
		if f.IsError() {
			out = append(out, f)
		}
	}
	return out
}

// Warnings returns only the warning-level findings.
func (vf ValidationFindings) Warnings() ValidationFindings {
	if len(vf) == 0 {
		return nil
	}
	var out ValidationFindings
	for _, f := range vf {
		if f.IsWarning() {
			out = append(out, f)
		}
	}
	return out
}

// ByRuleID returns findings matching the given rule ID.
func (vf ValidationFindings) ByRuleID(ruleID string) ValidationFindings {
	if len(vf) == 0 {
		return nil
	}
	var out ValidationFindings
	for _, f := range vf {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// RuleIDs returns unique rule IDs across all findings.
func (vf ValidationFindings) RuleIDs() []string {
	if len(vf) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(vf))
	var out []string
	for _, f := range vf {
		if _, ok := seen[f.RuleID]; !ok {
			seen[f.RuleID] = struct{}{}
			out = append(out, f.RuleID)
		}
	}
	return out
}

// ValidationResult is the typed outcome of a structural validation.
type ValidationResult struct {
	// Valid is true when no errors were found (warnings are acceptable).
	Valid bool

	// ErrorCount is the number of error-level findings.
	ErrorCount int

	// WarningCount is the number of warning-level findings.
	WarningCount int

	// ControlsChecked is the number of controls loaded and checked.
	ControlsChecked int

	// SnapshotsChecked is the number of snapshots loaded and checked.
	SnapshotsChecked int

	// AssetObservations is the number of asset observations across all snapshots.
	AssetObservations int

	// Findings is every diagnostic finding (errors and warnings).
	Findings ValidationFindings
}

// IsValid reports whether validation succeeded without error-level findings.
func (r *ValidationResult) IsValid() bool {
	return r != nil && r.Valid
}

// HasErrors reports whether there are any error-level findings.
func (r *ValidationResult) HasErrors() bool {
	return r != nil && r.ErrorCount > 0
}

// HasWarnings reports whether there are any warning-level findings.
func (r *ValidationResult) HasWarnings() bool {
	return r != nil && r.WarningCount > 0
}

// TotalFindings returns the combined count of error and warning findings.
func (r *ValidationResult) TotalFindings() int {
	if r == nil {
		return 0
	}
	return r.ErrorCount + r.WarningCount
}

// IsClean reports whether there are zero errors and zero warnings.
func (r *ValidationResult) IsClean() bool {
	return r != nil && r.TotalFindings() == 0
}

// HasCheckedControls reports whether any controls were loaded and checked.
func (r *ValidationResult) HasCheckedControls() bool {
	return r != nil && r.ControlsChecked > 0
}

// HasCheckedSnapshots reports whether any snapshots were loaded and checked.
func (r *ValidationResult) HasCheckedSnapshots() bool {
	return r != nil && r.SnapshotsChecked > 0
}

// Errors returns only the error-level findings from the result.
func (r *ValidationResult) Errors() ValidationFindings {
	if r == nil {
		return nil
	}
	return r.Findings.Errors()
}

// Warnings returns only the warning-level findings from the result.
func (r *ValidationResult) Warnings() ValidationFindings {
	if r == nil {
		return nil
	}
	return r.Findings.Warnings()
}

// Validate runs structural validation on the observation snapshots and
// control definitions. Equivalent to `stave lint` on the command
// line, minus CLI concerns (formatting, exit codes, hints).
func Validate(ctx context.Context, cfg ValidateConfig) (*ValidationResult, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("stave.Validate: ValidateConfig.SnapshotsDir is required")
	}

	obsLoader := observations.NewObservationLoader()
	ctlLoader := ctlyaml.NewControlLoader(
		ctlyaml.WithAliasResolver(builtinpredicate.ResolverFunc()),
	)
	celEval, _, err := stavecel.NewPredicateEvalWithCompiler()
	if err != nil {
		return nil, fmt.Errorf("stave.Validate: init CEL evaluator: %w", err)
	}

	runner := appvalidation.NewRun(obsLoader, ctlLoader)
	runner.BuiltinCatalog = func() ([]policy.ControlDefinition, error) {
		store := ctlbuiltin.NewControlStore(
			ctlbuiltin.EmbeddedFS(), "embedded",
			ctlbuiltin.WithAliasResolver(builtinpredicate.ResolverFunc()),
		)
		return store.All()
	}

	runCfg := appvalidation.Config{
		ControlsDir:     cfg.ControlsDir,
		ObservationsDir: cfg.SnapshotsDir,
		PredicateParser: ctlyaml.ParsePredicate,
		PredicateEval:   celEval,
	}

	report, err := runner.Execute(ctx, runCfg)
	if err != nil {
		return nil, fmt.Errorf("stave.Validate: %w", err)
	}

	return buildValidationResult(report), nil
}

func buildValidationResult(r *appvalidation.Report) *ValidationResult {
	result := &ValidationResult{
		Valid:             r.Valid(),
		ControlsChecked:   r.Summary.ControlsLoaded,
		SnapshotsChecked:  r.Summary.SnapshotsLoaded,
		AssetObservations: r.Summary.AssetObservationsLoaded,
	}

	if r.Diagnostics != nil {
		for _, f := range r.Diagnostics.Findings {
			vf := ValidationFinding{
				RuleID:      string(f.RuleID),
				Message:     f.Message,
				Remediation: f.Remediation,
			}
			if f.Severity == diag.SeverityError {
				vf.Severity = ValidationSeverityError
				result.ErrorCount++
			} else {
				vf.Severity = ValidationSeverityWarning
				result.WarningCount++
			}
			result.Findings = append(result.Findings, vf)
		}
	}

	return result
}
