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
	Findings []ValidationFinding
}

// ValidationFinding is one diagnostic issue found during validation.
type ValidationFinding struct {
	// RuleID identifies the validation rule that fired.
	RuleID string

	// Severity is "error" or "warning".
	Severity string

	// Message describes the issue.
	Message string

	// Remediation is a suggested fix.
	Remediation string
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
				vf.Severity = "error"
				result.ErrorCount++
			} else {
				vf.Severity = "warning"
				result.WarningCount++
			}
			result.Findings = append(result.Findings, vf)
		}
	}

	return result
}
