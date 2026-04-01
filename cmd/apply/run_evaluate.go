package apply

import (
	"context"
	"fmt"
	"io"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	appeval "github.com/sufield/stave/internal/app/eval"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
)

// executeEvaluation builds dependencies, runs the evaluation, and writes output.
func executeEvaluation(ctx context.Context, ec evalContext) (EvaluateResult, error) {
	progress := ec.Runtime.BeginCountedProgress("apply controls against observations")
	defer progress.Done()

	builder := NewBuilder(ec.Logger, ec.Opts, ec.Params, ec.IO)
	builder.NewFindingWriter = ec.Provider.NewFindingWriter
	builder.NewCtlRepo = ec.Provider.NewControlRepo
	builder.NewStdinObsRepo = ec.Provider.NewStdinObsRepo
	builder.ProjectConfig = ec.ProjectConfig
	builder.ProjectConfigPath = ec.ProjectConfigPath
	builder.OnObsProgress = progress.Update

	deps, err := builder.Build(ctx, ec.Plan)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("build evaluation dependencies: %w", err)
	}
	defer deps.Close()

	result, status, err := deps.Runner.Execute(ctx, deps.Config)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("execute evaluation: %w", err)
	}

	pipeline := &appeval.OutputPipeline{
		Marshaler: deps.Runner.Marshaler,
		Enricher:  deps.Runner.EnrichFn,
		Logger:    ec.Logger,
	}
	if err := pipeline.Run(ctx, deps.Config.Output, result); err != nil {
		return EvaluateResult{}, fmt.Errorf("run output pipeline: %w", err)
	}

	return BuildEvaluateResult(status, deps.Config.ControlsDir, deps.Config.ObservationsDir), nil
}

// runStrictIntegrityCheck ensures internal pack integrity when --strict is set.
func runStrictIntegrityCheck(strict bool, stdout, stderr io.Writer) error {
	if !strict {
		return nil
	}

	rt := ui.NewRuntime(stdout, stderr)
	done := rt.BeginProgress("perform strict integrity checks")
	defer done()

	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return fmt.Errorf("load default pack registry: %w", err)
	}
	if err := reg.ValidateStrict(ctlbuiltin.EmbeddedFS()); err != nil {
		return ui.WithNextCommand(err, "stave packs list")
	}
	return nil
}
