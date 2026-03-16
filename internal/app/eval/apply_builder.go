package eval

import (
	"context"
	"io"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// ApplyDeps holds wired dependencies for the apply workflow.
type ApplyDeps struct {
	Runner EvaluateRunner
	Config EvaluateConfig
}

// Close releases assets held by ApplyDeps.
func (d *ApplyDeps) Close() {}

// ApplyBuilderInput holds all pre-resolved inputs needed to build apply
// dependencies. All cmd-layer resolution (provider calls, project config
// lookup, git status, exemption loading) must be done by the caller.
type ApplyBuilderInput struct {
	Ctx    context.Context
	Stdout io.Writer
	Stderr io.Writer

	Plan EvaluationPlan

	// Adapters (pre-built by caller)
	Marshaler appcontracts.FindingMarshaler
	ObsLoader appcontracts.ObservationRepository
	CtlLoader appcontracts.ControlRepository
	EnrichFn  appcontracts.EnrichFunc

	// Runtime parameters
	MaxUnsafe         time.Duration
	Clock             ports.Clock
	Hasher            ports.Digester
	AllowUnknownInput bool
	ExemptionConfig   *policy.ExemptionConfig
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
	ToolVersion       string

	// Project scope
	ControlsDir     string
	ProjectConfig   ProjectConfigInput
	GitMetadata     *evaluation.GitInfo
	ControlFilters  ControlFilter
}

// BuildApplyDeps assembles ApplyDeps from fully resolved inputs.
// This function has no cmd-layer dependencies.
func BuildApplyDeps(in ApplyBuilderInput) (*ApplyDeps, error) {
	ctx := in.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	built, err := BuildDependencies(BuildDependenciesInput{
		Plan:    in.Plan,
		Context: ctx,
		Adapters: Adapters{
			FindingMarshaler:  in.Marshaler,
			EnrichFn:          in.EnrichFn,
			ObservationLoader: in.ObsLoader,
			ControlLoader:     in.CtlLoader,
		},
		Runtime: RuntimeConfig{
			MaxUnsafe:         in.MaxUnsafe,
			Clock:             in.Clock,
			Hasher:            in.Hasher,
			ToolVersion:       in.ToolVersion,
			AllowUnknownInput: in.AllowUnknownInput,
			ExemptionConfig:   in.ExemptionConfig,
			PredicateParser:   in.PredicateParser,
		},
		Writers: OutputWriters{
			Stdout: in.Stdout,
			Stderr: in.Stderr,
		},
		Project: ProjectScope{
			Config:      in.ProjectConfig,
			GitMetadata: in.GitMetadata,
			Filters:     in.ControlFilters,
			ControlsDir: in.ControlsDir,
		},
	})
	if err != nil {
		return nil, err
	}

	return &ApplyDeps{Runner: built.Runner, Config: built.Config}, nil
}
