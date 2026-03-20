package shared

import (
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// Loader handles the retrieval and validation of Stave artifacts from the filesystem.
type Loader struct {
	envelope appcontracts.FileEnvelopeLoader
	baseline appcontracts.FileBaselineLoader
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
