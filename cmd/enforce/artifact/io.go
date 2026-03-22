package artifact

import (
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// fileEnvelopeLoader loads a safety-envelope evaluation from a file path.
type fileEnvelopeLoader interface {
	LoadEnvelopeFromFile(path string) (*safetyenvelope.Evaluation, error)
}

// fileBaselineLoader loads an evaluation baseline from a file path.
type fileBaselineLoader interface {
	LoadBaselineFromFile(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error)
}

// Loader handles the retrieval and validation of Stave artifacts from the filesystem.
type Loader struct {
	envelope fileEnvelopeLoader
	baseline fileBaselineLoader
}

// NewLoader initializes a standard artifact loader.
func NewLoader() *Loader {
	adapter := evaljson.NewLoader()
	return &Loader{envelope: adapter, baseline: adapter}
}

// Evaluation loads and validates a JSON safety envelope containing evaluation results.
func (l *Loader) Evaluation(path string) (*safetyenvelope.Evaluation, error) {
	return l.envelope.LoadEnvelopeFromFile(path)
}

// Baseline loads a baseline finding file and ensures findings are sorted deterministically.
func (l *Loader) Baseline(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	return l.baseline.LoadBaselineFromFile(path, expectedKind)
}
