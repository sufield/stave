package workflow

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/ports"
)

// EvaluateInput holds loaded models and runtime options for evaluation processing.
type EvaluateInput struct {
	Controls          []policy.ControlDefinition
	Snapshots         []asset.Snapshot
	MaxUnsafeDuration time.Duration
	Clock             ports.Clock
	Hasher            ports.Digester
	ExemptionConfig   *policy.ExemptionConfig
	ExceptionConfig   *policy.ExceptionConfig
	StaveVersion      string
	InputHashes       *evaluation.InputHashes
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
	Metadata          evaluation.Metadata

	// CELEvaluator evaluates predicates using the CEL engine.
	CELEvaluator policy.PredicateEval
}

// Evaluate runs domain evaluation over already-loaded inputs.
func Evaluate(input EvaluateInput) (evaluation.Result, error) {
	catalog := policy.NewCatalog(input.Controls)
	runner := engine.Runner{
		Controls:          catalog.List(),
		MaxUnsafeDuration: input.MaxUnsafeDuration,
		Clock:             input.Clock,
		Hasher:            input.Hasher,
		Exemptions:        input.ExemptionConfig,
		Exceptions:        input.ExceptionConfig,
		PredicateParser:   input.PredicateParser,
		CELEvaluator:      input.CELEvaluator,
	}
	result, err := runner.Evaluate(input.Snapshots, engine.EvaluateOptions{
		StaveVersion: input.StaveVersion,
		InputHashes:  input.InputHashes,
	})
	if err != nil {
		return evaluation.Result{}, err
	}
	result.Metadata = input.Metadata
	return result, nil
}
