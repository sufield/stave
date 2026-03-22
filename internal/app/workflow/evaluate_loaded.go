package workflow

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// EvaluationRequest encapsulates loaded models and runtime options for evaluation.
type EvaluationRequest struct {
	Controls          []policy.ControlDefinition
	Snapshots         []asset.Snapshot
	MaxUnsafeDuration time.Duration
	Clock             ports.Clock
	Hasher            ports.Digester
	StaveVersion      string
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
	CELEvaluator      policy.PredicateEval
}

// EvaluateLoaded evaluates already-loaded controls and snapshots.
// This keeps command adapters from directly constructing domain evaluators.
func EvaluateLoaded(req EvaluationRequest) (evaluation.Result, error) {
	if req.Clock == nil {
		req.Clock = ports.NewRealClock()
	}

	return Evaluate(EvaluateInput{
		Controls:          req.Controls,
		Snapshots:         req.Snapshots,
		MaxUnsafeDuration: req.MaxUnsafeDuration,
		Clock:             req.Clock,
		Hasher:            req.Hasher,
		StaveVersion:      req.StaveVersion,
		PredicateParser:   req.PredicateParser,
		CELEvaluator:      req.CELEvaluator,
	})
}
