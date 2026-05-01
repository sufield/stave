package compose

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/report"
)

// LoadEvaluation resolves an ArtifactLoader from the factory and reads a
// previously persisted assessment envelope from path.
func LoadEvaluation(ctx context.Context, newLoader ArtifactLoaderFactory, path string) (*report.Assessment, error) {
	loader, err := newLoader()
	if err != nil {
		return nil, fmt.Errorf("create artifact loader: %w", err)
	}
	return loader.Evaluation(ctx, path)
}
