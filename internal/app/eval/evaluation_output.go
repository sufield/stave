package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

// OutputPipeline handles the Enrich → Marshal → Write sequence for
// evaluation results.
type OutputPipeline struct {
	Marshaler appcontracts.FindingMarshaler
	Enricher  appcontracts.EnrichFunc
	Logger    *slog.Logger
}

// Run executes the pipeline, writing the marshaled result to w.
func (p *OutputPipeline) Run(ctx context.Context, w io.Writer, result evaluation.Audit) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	enriched, err := runStep(p.Logger, "enrich", func() (appcontracts.EnrichedResult, error) {
		return p.Enricher(result)
	})
	if err != nil {
		return fmt.Errorf("enrich: %w", err)
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	data, err := runStep(p.Logger, "marshal", func() ([]byte, error) {
		return p.Marshaler.MarshalFindings(enriched)
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	if len(data) == 0 {
		return fmt.Errorf("no output generated")
	}

	_, err = runStep(p.Logger, "write", func() (int, error) {
		return w.Write(data)
	})
	return err
}

// runStep executes fn with optional timing logs.
func runStep[T any](logger *slog.Logger, name string, fn func() (T, error)) (T, error) {
	if logger != nil {
		logger.Debug("step starting", "step", name)
		start := time.Now()
		defer func() {
			logger.Debug("step completed", "step", name, "duration", time.Since(start))
		}()
	}
	return fn()
}
