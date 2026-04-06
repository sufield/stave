package report

import (
	"context"

	corereport "github.com/sufield/stave/internal/core/report"
)

// EvaluationLoaderFunc loads a safety envelope evaluation from a path.
type EvaluationLoaderFunc func(ctx context.Context, path string) (*corereport.Assessment, error)

// EvaluationLoader loads a persisted evaluation artifact.
type EvaluationLoader struct {
	LoadEval EvaluationLoaderFunc
}

// LoadEvaluation loads a safety envelope evaluation artifact.
func (l *EvaluationLoader) LoadEvaluation(ctx context.Context, path string) (*corereport.Assessment, error) {
	return l.LoadEval(ctx, path)
}
