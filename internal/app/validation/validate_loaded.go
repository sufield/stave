package validation

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
)

// Input holds loaded models and runtime options for validation processing.
type Input struct {
	Controls          []policy.ControlDefinition
	Snapshots         []asset.Snapshot
	MaxUnsafeDuration time.Duration
	NowTime           time.Time
	PredicateParser   policy.PredicateParser
	PredicateEval     policy.PredicateEval
}

// Summary provides counts over loaded models.
type Summary struct {
	ControlsLoaded             int
	SnapshotsLoaded            int
	AssetObservationsLoaded    int
	IdentityObservationsLoaded int
}

// Report contains validation issues plus computed summary counts.
type Report struct {
	Diagnostics *diag.Report
	Summary     Summary
}

// Valid returns true if there are no error diagnostics.
func (r *Report) Valid() bool {
	return !r.ensureDiagnostics().HasErrors()
}

// HasWarnings returns true if there are warning diagnostics.
func (r *Report) HasWarnings() bool {
	return r.ensureDiagnostics().HasWarnings()
}

func (r *Report) ensureDiagnostics() *diag.Report {
	if r == nil {
		return diag.NewResult()
	}
	if r.Diagnostics == nil {
		r.Diagnostics = diag.NewResult()
	}
	return r.Diagnostics
}

// ValidateLoaded runs domain validation over already-loaded inputs.
func ValidateLoaded(input Input) Report {
	summary := Summary{
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
			issues.AddAll(input.Controls[i].Validate())
		}
	}

	// 2. Validate snapshots.
	issues.AddAll(asset.Snapshots(input.Snapshots).ValidateAll(input.NowTime, input.MaxUnsafeDuration))

	// 3. Cross-model consistency checks.
	if len(input.Controls) > 0 && len(input.Snapshots) > 0 {
		issues.AddAll(policy.CheckEffectiveness(input.Controls, input.Snapshots, input.PredicateEval))
	}

	return Report{
		Diagnostics: issues,
		Summary:     summary,
	}
}
