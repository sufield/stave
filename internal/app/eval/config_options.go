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
	return func(cfg *EvaluateConfig) {
		cfg.Output = output
		cfg.Stderr = stderr
		cfg.Clock = clock
		cfg.StaveVersion = toolVersion
	}
}

// WithMaxUnsafeDuration constructs the withmaxunsafeduration component.
func WithMaxUnsafeDuration(maxUnsafeDuration time.Duration) Option {
	return func(cfg *EvaluateConfig) {
		cfg.MaxUnsafeDuration = maxUnsafeDuration
	}
}

// WithAllowUnknownInput constructs the withallowunknowninput component.
func WithAllowUnknownInput(allow bool) Option {
	return func(cfg *EvaluateConfig) {
		cfg.AllowUnknownInput = allow
	}
}

// WithExemptionConfig constructs the withexemptionconfig component.
func WithExemptionConfig(exemptionConfig *policy.ExemptionConfig) Option {
	return func(cfg *EvaluateConfig) {
		cfg.ExemptionConfig = exemptionConfig
	}
}

// WithExceptionConfig constructs the withexceptionconfig component.
func WithExceptionConfig(exceptionConfig *policy.ExceptionConfig) Option {
	return func(cfg *EvaluateConfig) {
		cfg.ExceptionConfig = exceptionConfig
	}
}

// WithPreloadedControls constructs the withpreloadedcontrols component.
func WithPreloadedControls(controls []policy.ControlDefinition) Option {
	cloned := slices.Clone(controls)
	return func(cfg *EvaluateConfig) {
		cfg.PreloadedControls = cloned
	}
}

// WithControlSource constructs the withcontrolsource component.
func WithControlSource(source evaluation.ControlSourceInfo) Option {
	return func(cfg *EvaluateConfig) {
		cfg.Metadata.ControlSource = source
	}
}

// WithGitMetadata constructs the withgitmetadata component.
func WithGitMetadata(git *evaluation.GitInfo) Option {
	return func(cfg *EvaluateConfig) {
		cfg.Metadata.Git = git
	}
}

// WithPredicateParser constructs the withpredicateparser component.
func WithPredicateParser(fn func(any) (*policy.UnsafePredicate, error)) Option {
	return func(cfg *EvaluateConfig) {
		cfg.PredicateParser = fn
	}
}

// WithCELEvaluator constructs the withcelevaluator component.
func WithCELEvaluator(fn policy.PredicateEval) Option {
	return func(cfg *EvaluateConfig) {
		cfg.CELEvaluator = fn
	}
}

// WithHasher constructs the withhasher component.
func WithHasher(h ports.Digester) Option {
	return func(cfg *EvaluateConfig) {
		cfg.Hasher = h
	}
}
