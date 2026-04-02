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
// Returns *safetyenvelope.Evaluation as any to keep the use case decoupled.
func (l *EvaluationLoader) LoadEvaluation(ctx context.Context, path string) (any, error) {
	eval, err := l.LoadEval(ctx, path)
	if err != nil {
		return nil, err
	}
	return eval, nil
}

// TypedEvaluation extracts the concrete evaluation from a ReportResponse.
func TypedEvaluation(data any) (*safetyenvelope.Evaluation, bool) {
	eval, ok := data.(*safetyenvelope.Evaluation)
	return eval, ok
}
