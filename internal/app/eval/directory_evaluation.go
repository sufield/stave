package eval

import (
	"context"
	"fmt"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
)

// DirectoryEvaluationRequest describes a loaded-on-demand evaluation over an
// observations directory.
type DirectoryEvaluationRequest struct {
	Context           context.Context
	ObservationsDir   string
	Controls          []policy.ControlDefinition
	MaxUnsafeDuration time.Duration
	Clock             ports.Clock
	AllowUnknownType  bool
	StaveVersion      string
	ObservationLoader appcontracts.ObservationRepository
	CELEvaluator      policy.PredicateEval
}

// RunDirectoryEvaluation loads snapshots and evaluates them against controls.
func RunDirectoryEvaluation(req DirectoryEvaluationRequest) (*evaluation.Result, int, error) {
	if req.ObservationLoader == nil {
		return nil, 0, fmt.Errorf("observation loader is required")
	}
	ctx := req.Context

	loadResult, err := req.ObservationLoader.LoadSnapshots(ctx, req.ObservationsDir)
	if err != nil {
		return nil, 0, fmt.Errorf("load observations from %s: %w", req.ObservationsDir, err)
	}
	snapshots := loadResult.Snapshots
	if len(snapshots) == 0 {
		return nil, 0, fmt.Errorf("%w: no snapshots in %s", ErrNoSnapshots, req.ObservationsDir)
	}

	if err = ValidateSourceTypeCompatibility(snapshots, req.AllowUnknownType, nil); err != nil {
		return nil, 0, fmt.Errorf("source_type compatibility in %s: %w", req.ObservationsDir, err)
	}

	result, err := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:          req.Controls,
		Snapshots:         snapshots,
		MaxUnsafeDuration: req.MaxUnsafeDuration,
		Clock:             req.Clock,
		StaveVersion:      req.StaveVersion,
		CELEvaluator:      req.CELEvaluator,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("evaluation failed: %w", err)
	}

	return &result, len(snapshots), nil
}
