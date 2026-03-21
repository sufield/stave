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

// RunOutputPipeline executes the Enrich → Marshal → Write sequence for
// evaluation results.
func RunOutputPipeline(
	ctx context.Context,
	out io.Writer,
	result evaluation.Result,
	marshaler appcontracts.FindingMarshaler,
	enrichFn appcontracts.EnrichFunc,
	logger *slog.Logger,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	enriched, err := runStep(logger, "enrich", func() (appcontracts.EnrichedResult, error) {
		return enrichFn(result)
	})
	if err != nil {
		return fmt.Errorf("failed to write findings: %w", err)
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	bytes, err := runStep(logger, "marshal", func() ([]byte, error) {
		return marshaler.MarshalFindings(enriched)
	})
	if err != nil {
		return fmt.Errorf("failed to write findings: marshal findings: %w", err)
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	if len(bytes) == 0 {
		return fmt.Errorf("failed to write findings: no bytes to write")
	}

	_, err = runStep(logger, "write", func() (int, error) {
		return out.Write(bytes)
	})
	if err != nil {
		return fmt.Errorf("failed to write findings: write output: %w", err)
	}
	return nil
}

// runStep executes fn with optional logging and panic recovery.
func runStep[T any](logger *slog.Logger, name string, fn func() (T, error)) (result T, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero T
			result = zero
			err = fmt.Errorf("panic in step %q: %v", name, r)
		}
	}()

	if logger != nil {
		logger.Debug("step starting", "step", name)
		start := time.Now()
		defer func() {
			logger.Debug("step completed", "step", name,
				"duration", time.Since(start), "error", err)
		}()
	}

	return fn()
}
