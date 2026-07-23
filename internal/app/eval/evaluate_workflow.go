package eval

import (
	"context"
	"fmt"
	"log/slog"
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

// resolveDependencies normalises the optional dependency slots so
// every evaluation component has at least a no-op implementation.
// Centralises the "fallback to safe default + warn the operator
// about the degraded mode" pattern instead of letting each Evaluate
// call site re-implement the nil-check ladder. The warns surface in
// -v output so an inconclusive verdict cluster is traceable to the
// missing dependency rather than read as a real evaluation failure.
func (input *EvaluateInput) resolveDependencies() {
	if input == nil {
		return
	}
	if input.PredicateParser == nil {
		slog.Warn("eval.Evaluate: PredicateParser is nil; falling back to no-op parser — predicates will not classify")
		input.PredicateParser = noopPredicateParser
	}
	if input.CELEvaluator == nil {
		slog.Warn("eval.Evaluate: CELEvaluator is nil; falling back to inconclusive evaluator — CEL predicates will not fire")
		input.CELEvaluator = inconclusiveCELEvaluator
	}
}

// BuildAssessorOptions returns the engine option list derived from the
// inputs on this EvaluateInput. The catalog, parser, and CEL evaluator
// are passed in so the caller can supply already-resolved fallbacks
// (noopPredicateParser, inconclusiveCELEvaluator) without
// BuildAssessorOptions reaching back into package-level helpers — the
// fallback policy stays in Evaluate where it is documented.
//
// Centralising the option list on EvaluateInput keeps the
// "which fields drive which engine option" mapping in one place, so
// adding a new EvaluateInput field is a single-site edit instead of a
// scan-and-update across every caller that constructs an Assessor.
func (i *EvaluateInput) BuildAssessorOptions(
	catalog *policy.Catalog,
	parser policy.PredicateParser,
	celEval policy.PredicateEval,
	tracer ports.Tracer,
) []engine.AssessorOption {
	opts := []engine.AssessorOption{
		engine.WithControls(catalog.List()),
		engine.WithSLAThreshold(i.MaxUnsafeDuration),
		engine.WithClock(i.Clock),
		// Hasher must be injected from the cmd/ composition root —
		// neither core/ nor app/ can import internal/platform/crypto
		// under the hexagonal-architecture rules. FingerprintPolicy()
		// returns "" when Hasher is nil, so omitting it is a soft
		// degradation.
		engine.WithHasher(i.Hasher),
		engine.WithExemptions(i.ExemptionConfig),
		engine.WithExceptions(i.ExceptionConfig),
		engine.WithAcknowledgments(i.AcknowledgmentConfig),
		engine.WithPredicateParser(parser),
		engine.WithPredicateEval(celEval),
		engine.WithTracer(tracer),
	}
	if i.Confidence.HighMultiplier > 0 {
		opts = append(opts, engine.WithConfidence(i.Confidence))
	}
	return opts
}

// Evaluate runs domain evaluation over already-loaded inputs.
//
// ctx flows down to engine.Assessor.Assess so a long-running assessment
// (large catalog × asset matrix) honours operator cancellation and
// upstream deadlines instead of running to completion silently.
func Evaluate(ctx context.Context, input EvaluateInput) (evaluation.ComplianceReport, error) {
	input.resolveDependencies()
	catalog := policy.NewCatalog(input.Controls)
	opts := input.BuildAssessorOptions(catalog, input.PredicateParser, input.CELEvaluator, input.Tracer)
	runner := engine.NewAssessor(opts...)
	result, err := runner.Assess(ctx, derive.Pipeline(input.Snapshots), engine.AssessmentOptions{
		StaveVersion:     input.StaveVersion,
		InputHashes:      input.InputHashes,
		GenerateEvidence: input.GenerateEvidence,
	})
	if err != nil {
		return evaluation.ComplianceReport{}, fmt.Errorf("assess snapshots: %w", err)
	}
	result.Metadata = input.Metadata
	return result, nil
}

// EvaluationRequest encapsulates loaded models and runtime options for evaluation.
type EvaluationRequest struct {
	Controls             []policy.ControlDefinition
	Snapshots            []asset.Snapshot
	MaxUnsafeDuration    time.Duration
	Clock                ports.Clock
	Hasher               ports.Digester
	StaveVersion         string
	PredicateParser      func(any) (*policy.UnsafePredicate, error)
	CELEvaluator         policy.PredicateEval
	GenerateEvidence     bool
	Confidence           evaluation.ConfidenceCalculator
	ExemptionConfig      *policy.ExemptionConfig
	ExceptionConfig      *policy.ExceptionConfig
	AcknowledgmentConfig *policy.AcknowledgmentConfig
	InputHashes          *evaluation.InputHashes
	Metadata             evaluation.Metadata
	Tracer               ports.Tracer
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
// does not set a CELEvaluator. When the control declares a
// verdict_on_error, that verdict is returned without an error so the
// engine records a definitive PASS or VIOLATION instead of marking the
// control inconclusive. Controls without the field get the original
// inconclusive behavior (error return).
func inconclusiveCELEvaluator(ctl policy.ControlDefinition, a asset.Asset, _ []asset.CloudIdentity) (bool, error) {
	switch ctl.VerdictOnError {
	case "safe":
		return false, nil
	case "fail_closed":
		return true, nil
	default:
		return false, fmt.Errorf("no CEL evaluator configured (control %s, asset %s)", ctl.ID, a.ID)
	}
}

// EvaluateLoaded evaluates already-loaded controls and snapshots.
// This keeps command adapters from directly constructing domain evaluators.
func EvaluateLoaded(ctx context.Context, req EvaluationRequest) (evaluation.ComplianceReport, error) {
	if req.Clock == nil {
		req.Clock = ports.RealClock{}
	}
	if req.PredicateParser == nil {
		req.PredicateParser = noopPredicateParser
	}
	if req.CELEvaluator == nil {
		req.CELEvaluator = inconclusiveCELEvaluator
	}

	return Evaluate(ctx, EvaluateInput{
		Controls:             req.Controls,
		Snapshots:            req.Snapshots,
		MaxUnsafeDuration:    req.MaxUnsafeDuration,
		Confidence:           req.Confidence,
		Clock:                req.Clock,
		Hasher:               req.Hasher,
		ExemptionConfig:      req.ExemptionConfig,
		ExceptionConfig:      req.ExceptionConfig,
		AcknowledgmentConfig: req.AcknowledgmentConfig,
		StaveVersion:         req.StaveVersion,
		InputHashes:          req.InputHashes,
		PredicateParser:      req.PredicateParser,
		Metadata:             req.Metadata,
		CELEvaluator:         req.CELEvaluator,
		Tracer:               req.Tracer,
		GenerateEvidence:     req.GenerateEvidence,
	})
}
