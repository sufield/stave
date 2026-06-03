package artifacts

import (
	"context"
	"errors"
	"fmt"

	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// Loader handles the retrieval and validation of Stave artifacts from the filesystem.
type Loader struct {
	adapter *evaljson.Loader
}

var _ appcontracts.ArtifactLoader = (*Loader)(nil)

// NewLoader initializes a standard artifact loader.
func NewLoader() *Loader {
	return &Loader{adapter: &evaljson.Loader{}}
}

// Evaluation loads and validates a JSON safety envelope containing evaluation results.
func (l *Loader) Evaluation(ctx context.Context, path string) (*report.Assessment, error) {
	if path == "" {
		return nil, errors.New("evaluation path is required")
	}
	a, err := l.adapter.LoadEnvelopeFromFile(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("load evaluation %s: %w", path, err)
	}
	return a, nil
}

// Baseline loads a baseline finding file and ensures findings are sorted deterministically.
func (l *Loader) Baseline(ctx context.Context, path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	if path == "" {
		return nil, errors.New("baseline path is required")
	}
	b, err := l.adapter.LoadBaselineFromFile(ctx, path, expectedKind)
	if err != nil {
		return nil, fmt.Errorf("load baseline %s: %w", path, err)
	}
	return b, nil
}
