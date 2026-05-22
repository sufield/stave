package eval

import (
	"io"
	"slices"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
)

// WithRuntime constructs the withruntime component.
func WithRuntime(output, stderr io.Writer, clock ports.Clock, toolVersion string) Option {
	return func(cfg *AssessmentConfig) {
		cfg.Output = output
		cfg.Stderr = stderr
		cfg.Clock = clock
		cfg.BuildVersion = toolVersion
	}
}

// WithMaxUnsafeDuration constructs the withmaxunsafeduration component.
func WithMaxUnsafeDuration(maxUnsafeDuration time.Duration) Option {
	return func(cfg *AssessmentConfig) {
		cfg.SLAThreshold = maxUnsafeDuration
	}
}

// WithAllowUnknownInput constructs the withallowunknowninput component.
func WithAllowUnknownInput(allow bool) Option {
	return func(cfg *AssessmentConfig) {
		cfg.AcceptUnknownData = allow
	}
}

// WithExemptionConfig constructs the withexemptionconfig component.
func WithExemptionConfig(exemptionConfig *policy.ExemptionConfig) Option {
	return func(cfg *AssessmentConfig) {
		cfg.ExemptionRules = exemptionConfig
	}
}

// WithAcknowledgmentConfig sets the acknowledgment configuration.
func WithAcknowledgmentConfig(ackConfig *policy.AcknowledgmentConfig) Option {
	return func(cfg *AssessmentConfig) {
		cfg.AcknowledgmentRules = ackConfig
	}
}

// WithExceptionConfig constructs the withexceptionconfig component.
func WithExceptionConfig(exceptionConfig *policy.ExceptionConfig) Option {
	return func(cfg *AssessmentConfig) {
		cfg.ExceptionRules = exceptionConfig
	}
}

// WithPreloadedControls constructs the withpreloadedcontrols component.
func WithPreloadedControls(controls []policy.ControlDefinition) Option {
	cloned := slices.Clone(controls)
	return func(cfg *AssessmentConfig) {
		cfg.ActivePolicies = cloned
	}
}

// WithControlSource constructs the withcontrolsource component.
func WithControlSource(source evaluation.ControlSourceInfo) Option {
	return func(cfg *AssessmentConfig) {
		cfg.Metadata.ControlSource = source
	}
}


// WithSLAConfig sets the SLA policy for deadline enforcement on findings.
func WithSLAConfig(cfg *evaluation.SLAConfig) Option {
	return func(acfg *AssessmentConfig) {
		acfg.SLAConfig = cfg
	}
}

// WithChainDefs sets the chain definitions for compound risk detection.
func WithChainDefs(defs []policy.ChainDefinition) Option {
	cloned := slices.Clone(defs)
	return func(cfg *AssessmentConfig) {
		cfg.ChainDefs = cloned
	}
}

// WithPredicateParser constructs the withpredicateparser component.
func WithPredicateParser(fn func(any) (*policy.UnsafePredicate, error)) Option {
	return func(cfg *AssessmentConfig) {
		cfg.PredicateParser = fn
	}
}

// WithCELEvaluator constructs the withcelevaluator component.
func WithCELEvaluator(fn policy.PredicateEval) Option {
	return func(cfg *AssessmentConfig) {
		cfg.PredicateEval = fn
	}
}

// WithHasher constructs the withhasher component.
func WithHasher(h ports.Digester) Option {
	return func(cfg *AssessmentConfig) {
		cfg.Hasher = h
	}
}

// WithTracer enables the logic audit trace.
func WithTracer(t ports.Tracer) Option {
	return func(cfg *AssessmentConfig) {
		cfg.Tracer = t
	}
}
