package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

// Pipeline chains context-aware steps with short-circuit error handling.
// The type parameter T is the data carrier passed through each step.
type Pipeline[T any] struct {
	ctx  context.Context
	data *T
	err  error
}

// NewPipeline creates a pipeline with the given context and data carrier.
func NewPipeline[T any](ctx context.Context, data *T) *Pipeline[T] {
	return &Pipeline[T]{ctx: ctx, data: data}
}

// Then executes the next step, short-circuiting on prior error or
// cancelled context.
func (p *Pipeline[T]) Then(step func(context.Context, *T) error) *Pipeline[T] {
	if p.err != nil {
		return p
	}
	if err := p.ctx.Err(); err != nil {
		p.err = err
		return p
	}
	p.err = step(p.ctx, p.data)
	return p
}

// Error returns the first error encountered in the pipeline.
func (p *Pipeline[T]) Error() error {
	return p.err
}

// PipelineData carries state through evaluation pipeline steps.
type PipelineData struct {
	Result   evaluation.Result
	Enriched appcontracts.EnrichedResult
	Bytes    []byte
	Output   io.Writer
}

// Step is a single pipeline operation that transforms PipelineData.
type Step func(ctx context.Context, d *PipelineData) error

// EnrichStep returns a Step that enriches evaluation results into findings.
func EnrichStep(enrichFn appcontracts.EnrichFunc) Step {
	return func(_ context.Context, d *PipelineData) error {
		d.Enriched = enrichFn(d.Result)
		return nil
	}
}

// MarshalStep returns a Step that marshals enriched findings into bytes.
func MarshalStep(marshaler appcontracts.FindingMarshaler) Step {
	return func(_ context.Context, d *PipelineData) error {
		var err error
		d.Bytes, err = marshaler.MarshalFindings(d.Enriched)
		if err != nil {
			return fmt.Errorf("marshal findings: %w", err)
		}
		return nil
	}
}

// WriteStep returns a Step that writes marshaled bytes to the output writer.
func WriteStep() Step {
	return func(_ context.Context, d *PipelineData) error {
		if len(d.Bytes) == 0 {
			return fmt.Errorf("no bytes to write")
		}
		if _, err := d.Output.Write(d.Bytes); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}
}

// WithLogging wraps a Step with debug-level logging of start, duration, and errors.
func WithLogging(logger *slog.Logger, name string, step Step) Step {
	if logger == nil {
		return step
	}
	return func(ctx context.Context, d *PipelineData) error {
		logger.Debug("pipeline step starting", "step", name)
		start := time.Now()
		err := step(ctx, d)
		logger.Debug("pipeline step completed", "step", name,
			"duration", time.Since(start), "error", err)
		return err
	}
}

// WithRecovery wraps a Step to convert panics into errors.
func WithRecovery(name string, step Step) Step {
	return func(ctx context.Context, d *PipelineData) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic in pipeline step %q: %v", name, r)
			}
		}()
		return step(ctx, d)
	}
}
