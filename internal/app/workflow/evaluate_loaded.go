package workflow

import (
	"time"

	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// EvaluationRequest encapsulates loaded models and runtime options for evaluation.
type EvaluationRequest struct {
	Controls        []policy.ControlDefinition
	Snapshots       []asset.Snapshot
	MaxUnsafe       time.Duration
	Clock           ports.Clock
	Hasher          ports.Digester
	ToolVersion     string
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	CELEvaluator    policy.PredicateEval
}

// EvaluateLoaded evaluates already-loaded controls and snapshots.
// This keeps command adapters from directly constructing domain evaluators.
func EvaluateLoaded(req EvaluationRequest) (evaluation.Result, error) {
	if req.Clock == nil {
		req.Clock = ports.NewRealClock()
	}

	return service.Evaluate(service.EvaluateInput{
		Controls:        req.Controls,
		Snapshots:       req.Snapshots,
		MaxUnsafe:       req.MaxUnsafe,
		Clock:           req.Clock,
		Hasher:          req.Hasher,
		ToolVersion:     req.ToolVersion,
		PredicateParser: req.PredicateParser,
		CELEvaluator:    req.CELEvaluator,
	})
}
