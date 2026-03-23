package artifact

import (
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
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
func (l *Loader) Evaluation(path string) (*safetyenvelope.Evaluation, error) {
	return l.adapter.LoadEnvelopeFromFile(path)
}

// Baseline loads a baseline finding file and ensures findings are sorted deterministically.
func (l *Loader) Baseline(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	return l.adapter.LoadBaselineFromFile(path, expectedKind)
}
