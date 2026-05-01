package report

import (
	"context"
	"errors"

	corereport "github.com/sufield/stave/internal/core/report"
)

// EvaluationLoaderFunc loads a safety envelope evaluation from a path.
type EvaluationLoaderFunc func(ctx context.Context, path string) (*corereport.Assessment, error)

// EvaluationLoader loads a persisted evaluation artifact.
type EvaluationLoader struct {
	loadEval EvaluationLoaderFunc
}

// NewEvaluationLoader constructs an EvaluationLoader. loader must
// be non-nil.
func NewEvaluationLoader(loader EvaluationLoaderFunc) (*EvaluationLoader, error) {
	if loader == nil {
		return nil, errors.New("report.NewEvaluationLoader: loader is nil")
	}
	return &EvaluationLoader{loadEval: loader}, nil
}

// LoadEvaluation loads a safety envelope evaluation artifact.
func (l *EvaluationLoader) LoadEvaluation(ctx context.Context, path string) (*corereport.Assessment, error) {
	return l.loadEval(ctx, path)
}
