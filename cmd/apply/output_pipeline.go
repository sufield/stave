package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
)

// RunOutputPipeline executes the Enrich → Marshal → Write pipeline for
// evaluation results. This is the cmd-layer counterpart to the pipeline
// that was previously embedded in the app layer's Execute method.
func RunOutputPipeline(
	ctx context.Context,
	out io.Writer,
	result evaluation.Result,
	marshaler appcontracts.FindingMarshaler,
	enrichFn appcontracts.EnrichFunc,
	logger *slog.Logger,
) error {
	wrap := func(name string, s PipelineStep) PipelineStep {
		s = WithRecovery(name, s)
		s = WithLogging(logger, name, s)
		return s
	}
	err := NewPipeline(ctx, &PipelineData{Result: result, Output: out}).
		Then(wrap("enrich", EnrichStep(enrichFn))).
		Then(wrap("marshal", MarshalStep(marshaler))).
		Then(wrap("write", WriteStep())).
		Error()
	if err != nil {
		return fmt.Errorf("failed to write findings: %w", err)
	}
	return nil
}
