package eval

import (
	"github.com/sufield/stave/internal/core/evaluation"
)

// Option applies a configuration setting to an AssessmentConfig.
// Options must be simple field assignments with no I/O or side effects.
type Option func(*AssessmentConfig)

// NewConfig assembles an AssessmentConfig from a plan and options.
// All resolution and validation must happen before calling NewConfig.
func NewConfig(plan EvaluationPlan, opts ...Option) AssessmentConfig {
	cfg := AssessmentConfig{
		InventoryConfig: InventoryConfig{
			PolicySource:    plan.ControlsPath,
			InventorySource: plan.ObservationsPath,
		},
		Metadata: evaluation.Metadata{
			ControlSource: evaluation.ControlSourceInfo{Source: evaluation.ControlSourceDir},
			ContextName:   plan.ContextName,
			ResolvedPaths: evaluation.ResolvedPaths{
				Controls:     plan.ControlsPath,
				Observations: plan.ObservationsPath,
			},
		},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}
