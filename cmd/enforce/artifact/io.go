package artifact

import (
	"context"
	"errors"

	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// Loader handles the retrieval and validation of Stave artifacts from the filesystem.
type Loader struct {
	adapter *evaljson.Loader
}

// NewLoader initializes a standard artifact loader.
func NewLoader() *Loader {
	return &Loader{adapter: &evaljson.Loader{}}
}

// Evaluation loads and validates a JSON safety envelope containing evaluation results.
func (l *Loader) Evaluation(ctx context.Context, path string) (*safetyenvelope.Evaluation, error) {
	if path == "" {
		return nil, errors.New("evaluation path is required")
	}
	return l.adapter.LoadEnvelopeFromFile(ctx, path)
}

// Baseline loads a baseline finding file and ensures findings are sorted deterministically.
func (l *Loader) Baseline(ctx context.Context, path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	if path == "" {
		return nil, errors.New("baseline path is required")
	}
	return l.adapter.LoadBaselineFromFile(ctx, path, expectedKind)
}
