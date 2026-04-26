package eval

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/derive"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/ports"
)

// EvaluateInput holds loaded models and runtime options for evaluation processing.
type EvaluateInput struct {
	Controls             []policy.ControlDefinition
	Snapshots            []asset.Snapshot
	MaxUnsafeDuration    time.Duration
	Confidence           evaluation.ConfidenceCalculator
	Clock                ports.Clock
	Hasher               ports.Digester
	ExemptionConfig      *policy.ExemptionConfig
	ExceptionConfig      *policy.ExceptionConfig
	AcknowledgmentConfig *policy.AcknowledgmentConfig
	StaveVersion         string
	InputHashes          *evaluation.InputHashes
	PredicateParser      func(any) (*policy.UnsafePredicate, error)
	Metadata             evaluation.Metadata

	// CELEvaluator evaluates predicates using the CEL engine.
	CELEvaluator policy.PredicateEval

	// Tracer enables the logic trace audit trail. When set, the engine
	// records every decision step for both PASS and VIOLATION verdicts.
	// Nil means no tracing (zero overhead via nopSpan).
	Tracer ports.Tracer

	// GenerateEvidence enables compliance evidence record generation.
	// When true, every finding and pass check produces structured
	// EvidenceRecords with regulatory citations and reasoning traces.
	GenerateEvidence bool
}

// Evaluate runs domain evaluation over already-loaded inputs.
func Evaluate(input EvaluateInput) (evaluation.ComplianceReport, error) {
	catalog := policy.NewCatalog(input.Controls)
	runner := engine.NewAssessor()
	runner.Controls = catalog.List()
	runner.SLAThreshold = input.MaxUnsafeDuration
	runner.Clock = input.Clock
	runner.Hasher = input.Hasher
	runner.Exemptions = input.ExemptionConfig
	runner.Exceptions = input.ExceptionConfig
	runner.Acknowledgments = input.AcknowledgmentConfig
	runner.PredicateParser = input.PredicateParser
	if runner.PredicateParser == nil {
		runner.PredicateParser = noopPredicateParser
	}
	runner.PredicateEval = input.CELEvaluator
	if runner.PredicateEval == nil {
		runner.PredicateEval = inconclusiveCELEvaluator
	}
	runner.Tracer = input.Tracer
	if input.Confidence.HighMultiplier > 0 {
		runner.Confidence = input.Confidence
	}
	result, err := runner.Assess(derive.Pipeline(input.Snapshots), engine.AssessmentOptions{
		StaveVersion:     input.StaveVersion,
		InputHashes:      input.InputHashes,
		GenerateEvidence: input.GenerateEvidence,
	})
	if err != nil {
		return evaluation.ComplianceReport{}, err
	}
	result.Metadata = input.Metadata
	return result, nil
}

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
	GenerateEvidence  bool
}

// noopPredicateParser is the fallback parser used when EvaluationRequest
// does not set one. Stave's domain code declares PredicateParser as a
// required dependency on the Assessor (see assessor.Assess preconditions)
// but the runtime never actually invokes the parser today. The fallback
// satisfies the precondition without forcing every caller — including
// tests that exercise non-predicate paths — to import the YAML parser.
func noopPredicateParser(_ any) (*policy.UnsafePredicate, error) {
	return &policy.UnsafePredicate{}, nil
}

// inconclusiveCELEvaluator is the fallback used when EvaluationRequest
// does not set a CELEvaluator. Returning an error here matches the
// downstream checkUnsafe semantics: each control becomes inconclusive
// rather than silently passing as "safe". Some flows (e.g. snapshot
// risk metrics that don't depend on per-asset findings) intentionally
// run without a real evaluator; the inconclusive path keeps their
// observable behavior unchanged after the Assessor's nil-precondition
// was added.
func inconclusiveCELEvaluator(ctl policy.ControlDefinition, a asset.Asset, _ []asset.CloudIdentity) (bool, error) {
	return false, fmt.Errorf("no CEL evaluator configured (control %s, asset %s)", ctl.ID, a.ID)
}

// EvaluateLoaded evaluates already-loaded controls and snapshots.
// This keeps command adapters from directly constructing domain evaluators.
func EvaluateLoaded(req EvaluationRequest) (evaluation.ComplianceReport, error) {
	if req.Clock == nil {
		req.Clock = ports.RealClock{}
	}
	if req.PredicateParser == nil {
		req.PredicateParser = noopPredicateParser
	}
	if req.CELEvaluator == nil {
		req.CELEvaluator = inconclusiveCELEvaluator
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
		GenerateEvidence:  req.GenerateEvidence,
	})
}
