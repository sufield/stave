package eval

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/sufield/stave/internal/app/capabilities"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
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
// By default, snapshots are required and source type compatibility is checked.
// Set OptionalSnapshots or SkipSourceTypeCheck to opt out.
type IntentEvaluationConfig struct {
	ControlsDir         string
	ObservationsDir     string
	RequireControls     bool
	SkipControlsLoad    bool // true when controls come from packs, not disk
	OptionalSnapshots   bool
	SkipSourceTypeCheck bool
	AllowUnknownInput   bool
	Stderr              io.Writer
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

// FirstError returns the first available artifact error.
func (r IntentEvaluationResult) FirstError() error {
	if r.ControlErr != nil {
		return r.ControlErr
	}
	return r.ObservationErr
}

// LoadArtifacts performs preflight artifact loading and optional compatibility checks.
// Controls and observations are loaded concurrently since they are independent I/O.
func (i *IntentEvaluation) LoadArtifacts(ctx context.Context, cfg IntentEvaluationConfig) IntentEvaluationResult {
	var (
		controls   []policy.ControlDefinition
		ctlErr     error
		loadResult appcontracts.LoadResult
		obsErr     error
		wg         sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		// When controls come from built-in packs, the controls directory
		// may not exist on disk. Skip loading entirely.
		if cfg.SkipControlsLoad {
			return
		}
		controls, ctlErr = appcontracts.LoadControls(ctx, i.ControlRepo, cfg.ControlsDir)
		if ctlErr == nil && cfg.RequireControls && len(controls) == 0 {
			ctlErr = fmt.Errorf("%w: no controls in %s (expected .yaml files with dsl_version: ctrl.v1)", ErrNoControls, cfg.ControlsDir)
		}
	}()
	go func() {
		defer wg.Done()
		loadResult, obsErr = appcontracts.LoadSnapshots(ctx, i.ObservationRepo, cfg.ObservationsDir)
		if obsErr == nil && !cfg.OptionalSnapshots && len(loadResult.Snapshots) == 0 {
			obsErr = fmt.Errorf("%w: no snapshots in %s (expected .json files with schema_version: obs.v0.1)", ErrNoSnapshots, cfg.ObservationsDir)
		}
		if obsErr == nil && !cfg.SkipSourceTypeCheck {
			obsErr = validateSourceTypeCompatibility(loadResult.Snapshots, cfg.AllowUnknownInput, stderrWarnf(cfg.Stderr))
		}
	}()
	wg.Wait()

	return IntentEvaluationResult{
		Controls:       controls,
		ControlErr:     ctlErr,
		Snapshots:      loadResult.Snapshots,
		Hashes:         loadResult.Hashes,
		ObservationErr: obsErr,
	}
}

type sourceTypeVerdict int

const (
	sourceTypeOK sourceTypeVerdict = iota
	sourceTypeMissing
	sourceTypeUnsupported
)

func classifySnapshotSourceType(s asset.Snapshot) sourceTypeVerdict {
	if s.GeneratedBy == nil || s.GeneratedBy.SourceType == "" {
		return sourceTypeMissing
	}
	if !capabilities.IsSourceTypeSupported(s.GeneratedBy.SourceType) {
		return sourceTypeUnsupported
	}
	return sourceTypeOK
}

func handleSourceTypeIssue(i int, s asset.Snapshot, verdict sourceTypeVerdict, allowUnknown bool, warnf func(string, ...any)) error {
	switch verdict {
	case sourceTypeMissing:
		if allowUnknown {
			if warnf != nil {
				warnf("warning: snapshot[%d] has no generated_by.source_type, proceeding anyway\n", i)
			}
			return nil
		}
		return fmt.Errorf("%w: snapshot[%d] missing generated_by.source_type (use --allow-unknown-input to skip)", ErrSourceTypeMissing, i)
	case sourceTypeUnsupported:
		if allowUnknown {
			if warnf != nil {
				warnf("warning: snapshot[%d] has unsupported source_type %q, proceeding anyway\n", i, s.GeneratedBy.SourceType)
			}
			return nil
		}
		return fmt.Errorf("%w: snapshot[%d] has unsupported source_type %q (use --allow-unknown-input to skip)", ErrSourceTypeUnsupported, i, s.GeneratedBy.SourceType)
	default:
		return nil
	}
}

// validateSourceTypeCompatibility checks that all snapshots have supported source types.
func validateSourceTypeCompatibility(snapshots []asset.Snapshot, allowUnknownInput bool, warnf func(format string, args ...any)) error {
	for i, s := range snapshots {
		verdict := classifySnapshotSourceType(s)
		if verdict == sourceTypeOK {
			continue
		}
		if err := handleSourceTypeIssue(i, s, verdict, allowUnknownInput, warnf); err != nil {
			return err
		}
	}
	return nil
}

func stderrWarnf(stderr io.Writer) func(format string, args ...any) {
	if stderr == nil {
		return nil
	}
	return func(format string, args ...any) {
		_, _ = fmt.Fprintf(stderr, format, args...)
	}
}

// ValidateSourceTypeCompatibility validates generated_by.source_type values on snapshots.
func ValidateSourceTypeCompatibility(snapshots []asset.Snapshot, allowUnknownInput bool, stderr io.Writer) error {
	return validateSourceTypeCompatibility(snapshots, allowUnknownInput, stderrWarnf(stderr))
}
