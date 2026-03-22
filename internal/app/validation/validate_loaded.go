package validation

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// ValidationInput holds loaded models and runtime options for validation processing.
type ValidationInput struct {
	Controls          []policy.ControlDefinition
	Snapshots         []asset.Snapshot
	MaxUnsafeDuration time.Duration
	NowTime           time.Time
	PredicateParser   policy.PredicateParser
	PredicateEval     policy.PredicateEval
}

// ValidationSummary provides counts over loaded models.
type ValidationSummary struct {
	ControlsLoaded             int
	SnapshotsLoaded            int
	AssetObservationsLoaded    int
	IdentityObservationsLoaded int
}

// ValidationResult contains validation issues plus computed summary counts.
type ValidationResult struct {
	Diagnostics *diag.Result
	Summary     ValidationSummary
}

// Valid returns true if there are no error diagnostics.
func (r *ValidationResult) Valid() bool {
	return !r.ensureDiagnostics().HasErrors()
}

// HasWarnings returns true if there are warning diagnostics.
func (r *ValidationResult) HasWarnings() bool {
	return r.ensureDiagnostics().HasWarnings()
}

func (r *ValidationResult) ensureDiagnostics() *diag.Result {
	if r == nil {
		return diag.NewResult()
	}
	if r.Diagnostics == nil {
		r.Diagnostics = diag.NewResult()
	}
	return r.Diagnostics
}

// ValidateLoaded runs domain validation over already-loaded inputs.
func ValidateLoaded(input ValidationInput) ValidationResult {
	summary := ValidationSummary{
		ControlsLoaded:  len(input.Controls),
		SnapshotsLoaded: len(input.Snapshots),
	}
	for _, snap := range input.Snapshots {
		summary.AssetObservationsLoaded += len(snap.Assets)
		summary.IdentityObservationsLoaded += len(snap.Identities)
	}

	issues := diag.NewResult()

	// 1. Validate controls.
	if len(input.Controls) == 0 {
		issues.Add(diag.New(diag.CodeNoControls).
			Warning().
			Action("Add control YAML files to the directory").
			Build())
	} else {
		for i := range input.Controls {
			issues.AddAll(policy.ValidateControlDefinition(&input.Controls[i]))
		}
	}

	// 2. Validate snapshots.
	issues.AddAll(asset.Snapshots(input.Snapshots).ValidateAll(input.NowTime, input.MaxUnsafeDuration))

	// 3. Cross-model consistency checks.
	if len(input.Controls) > 0 && len(input.Snapshots) > 0 {
		issues.AddAll(policy.CheckControlEffectiveness(input.Controls, input.Snapshots, input.PredicateEval))
	}

	return ValidationResult{
		Diagnostics: issues,
		Summary:     summary,
	}
}
