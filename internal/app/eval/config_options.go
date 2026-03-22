package eval

import (
	"io"
	"slices"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

func WithRuntime(output, stderr io.Writer, clock ports.Clock, toolVersion string) Option {
	return func(cfg *EvaluateConfig) {
		cfg.Output = output
		cfg.Stderr = stderr
		cfg.Clock = clock
		cfg.StaveVersion = toolVersion
	}
}

func WithMaxUnsafeDuration(maxUnsafeDuration time.Duration) Option {
	return func(cfg *EvaluateConfig) {
		cfg.MaxUnsafeDuration = maxUnsafeDuration
	}
}

func WithAllowUnknownInput(allow bool) Option {
	return func(cfg *EvaluateConfig) {
		cfg.AllowUnknownInput = allow
	}
}

func WithExemptionConfig(exemptionConfig *policy.ExemptionConfig) Option {
	return func(cfg *EvaluateConfig) {
		cfg.ExemptionConfig = exemptionConfig
	}
}

func WithExceptionConfig(exceptionConfig *policy.ExceptionConfig) Option {
	return func(cfg *EvaluateConfig) {
		cfg.ExceptionConfig = exceptionConfig
	}
}

func WithPreloadedControls(controls []policy.ControlDefinition) Option {
	cloned := slices.Clone(controls)
	return func(cfg *EvaluateConfig) {
		cfg.PreloadedControls = cloned
	}
}

func WithControlSource(source evaluation.ControlSourceInfo) Option {
	return func(cfg *EvaluateConfig) {
		cfg.Metadata.ControlSource = source
	}
}

func WithGitMetadata(git *evaluation.GitInfo) Option {
	return func(cfg *EvaluateConfig) {
		cfg.Metadata.Git = git
	}
}

func WithPredicateParser(fn func(any) (*policy.UnsafePredicate, error)) Option {
	return func(cfg *EvaluateConfig) {
		cfg.PredicateParser = fn
	}
}

func WithCELEvaluator(fn policy.PredicateEval) Option {
	return func(cfg *EvaluateConfig) {
		cfg.CELEvaluator = fn
	}
}

func WithHasher(h ports.Digester) Option {
	return func(cfg *EvaluateConfig) {
		cfg.Hasher = h
	}
}
