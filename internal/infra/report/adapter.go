package report

import (
	"context"

	"github.com/sufield/stave/cmd/enforce/artifact"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// EvaluationLoader loads a persisted evaluation artifact.
type EvaluationLoader struct{}

// LoadEvaluation loads a safety envelope evaluation artifact.
// Returns *safetyenvelope.Evaluation as any to keep the use case decoupled.
func (l *EvaluationLoader) LoadEvaluation(ctx context.Context, path string) (any, error) {
	eval, err := artifact.NewLoader().Evaluation(ctx, fsutil.CleanUserPath(path))
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
