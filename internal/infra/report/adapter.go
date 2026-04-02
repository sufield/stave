package report

import (
	"context"

	"github.com/sufield/stave/internal/safetyenvelope"
)

// EvaluationLoaderFunc loads a safety envelope evaluation from a path.
type EvaluationLoaderFunc func(ctx context.Context, path string) (*safetyenvelope.Evaluation, error)

// EvaluationLoader loads a persisted evaluation artifact.
type EvaluationLoader struct {
	LoadEval EvaluationLoaderFunc
}

// LoadEvaluation loads a safety envelope evaluation artifact.
func (l *EvaluationLoader) LoadEvaluation(ctx context.Context, path string) (*safetyenvelope.Evaluation, error) {
	return l.LoadEval(ctx, path)
}
