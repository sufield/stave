package service

import (
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/engine"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// EvaluateInput holds loaded models and runtime options for evaluation processing.
type EvaluateInput struct {
	Controls        []policy.ControlDefinition
	Snapshots       []asset.Snapshot
	MaxUnsafe       time.Duration
	Clock           ports.Clock
	Hasher          ports.Digester
	ExemptionConfig *policy.ExemptionConfig
	ExceptionConfig *policy.ExceptionConfig
	ToolVersion     string
	InputHashes     *evaluation.InputHashes
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	Metadata        evaluation.Metadata

	// CELEvaluator evaluates predicates using the CEL engine.
	CELEvaluator engine.PredicateEvaluator
}

// Evaluate runs domain evaluation over already-loaded inputs.
func Evaluate(input EvaluateInput) (evaluation.Result, error) {
	runner := engine.Runner{
		Controls:        input.Controls,
		MaxUnsafe:       input.MaxUnsafe,
		Clock:           input.Clock,
		Hasher:          input.Hasher,
		Exemptions:      input.ExemptionConfig,
		Exceptions:      input.ExceptionConfig,
		ToolVersion:     input.ToolVersion,
		InputHashes:     input.InputHashes,
		PredicateParser: input.PredicateParser,
		CELEvaluator:    input.CELEvaluator,
	}
	result, err := runner.Evaluate(input.Snapshots)
	if err != nil {
		return evaluation.Result{}, err
	}
	result.Metadata = input.Metadata
	return result, nil
}
