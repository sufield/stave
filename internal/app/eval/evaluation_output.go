package eval

import (
	"context"
	"io"

	"github.com/sufield/stave/internal/domain/evaluation"
)

// writeOutput writes findings using the Enrich → Marshal → Write pipeline.
func (e *EvaluateRun) writeOutput(ctx context.Context, out io.Writer, result evaluation.Result) error {
	wrap := func(name string, s Step) Step {
		s = WithRecovery(name, s)
		s = WithLogging(e.Logger, name, s)
		return s
	}
	return NewPipeline(ctx, &PipelineData{Result: result, Output: out}).
		Then(wrap("enrich", EnrichStep(e.EnrichFn))).
		Then(wrap("marshal", MarshalStep(e.Marshaler))).
		Then(wrap("write", WriteStep())).
		Error()
}
