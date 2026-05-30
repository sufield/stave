package eval

import (
	"context"
	"errors"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// IntentEvaluation orchestrates preflight checks over incoming artifacts before
// they affect downstream evaluation results.
type IntentEvaluation struct {
	ObservationRepo appcontracts.ObservationRepository
	ControlRepo     appcontracts.ControlRepository
}

// NewIntentEvaluation creates an app-layer preflight use case.
func NewIntentEvaluation(obsRepo appcontracts.ObservationRepository, ctlRepo appcontracts.ControlRepository) *IntentEvaluation {
	return &IntentEvaluation{
		ObservationRepo: obsRepo,
		ControlRepo:     ctlRepo,
	}
}

// IntentEvaluationConfig controls artifact loading and preflight checks.
// By default, snapshots are required. Set OptionalSnapshots to opt out.
type IntentEvaluationConfig struct {
	ControlsDir       string
	ObservationsDir   string
	RequireControls   bool
	SkipControlsLoad  bool // true when controls come from packs, not disk
	OptionalSnapshots bool
}

// IntentEvaluationResult contains loaded artifacts and independent load errors.
type IntentEvaluationResult struct {
	Controls       []policy.ControlDefinition
	Snapshots      []asset.Snapshot
	Hashes         *evaluation.InputHashes
	ControlErr     error
	ObservationErr error
}

// HasErrors reports whether either artifact failed to load/validate.
func (r IntentEvaluationResult) HasErrors() bool {
	return r.ControlErr != nil || r.ObservationErr != nil
}

// FirstError returns the artifact error(s) seen during preflight.
// When both ControlErr and ObservationErr are non-nil they are
// joined with errors.Join so callers can errors.Is / errors.As
// against either, instead of silently dropping the second one.
// The function name predates the join behavior; kept stable so
// existing callers still compile.
func (r IntentEvaluationResult) FirstError() error {
	if r.ControlErr != nil && r.ObservationErr != nil {
		return errors.Join(r.ControlErr, r.ObservationErr)
	}
	if r.ControlErr != nil {
		return r.ControlErr
	}
	return r.ObservationErr
}

// LoadArtifacts performs preflight artifact loading and optional compatibility checks.
func (i *IntentEvaluation) LoadArtifacts(ctx context.Context, cfg IntentEvaluationConfig) IntentEvaluationResult {
	var (
		controls   []policy.ControlDefinition
		ctlErr     error
		loadResult appcontracts.LoadResult
		obsErr     error
	)

	// Load controls (skip when using built-in packs).
	if !cfg.SkipControlsLoad {
		controls, ctlErr = appcontracts.LoadControls(ctx, i.ControlRepo, cfg.ControlsDir)
		if ctlErr == nil && cfg.RequireControls && len(controls) == 0 {
			ctlErr = fmt.Errorf("%w: no controls in %s (expected .yaml files with dsl_version: ctrl.v1)", ErrNoControls, cfg.ControlsDir)
		}
	}

	// Load observations.
	loadResult, obsErr = appcontracts.LoadSnapshots(ctx, i.ObservationRepo, cfg.ObservationsDir)
	if obsErr == nil && !cfg.OptionalSnapshots && len(loadResult.Snapshots) == 0 {
		obsErr = fmt.Errorf("%w: no snapshots in %s (expected .json files with schema_version: obs.v0.1)", ErrNoSnapshots, cfg.ObservationsDir)
	}

	return IntentEvaluationResult{
		Controls:       controls,
		ControlErr:     ctlErr,
		Snapshots:      loadResult.Snapshots,
		Hashes:         loadResult.Hashes,
		ObservationErr: obsErr,
	}
}
