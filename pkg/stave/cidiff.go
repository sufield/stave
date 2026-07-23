package stave

import (
	"context"
	"fmt"

	infrabaseline "github.com/sufield/stave/internal/adapters/baseline"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/reporting"
)

// CIDiffResponse is the facade re-export of reporting.CIDiffResponse.
type CIDiffResponse = reporting.CIDiffResponse

// CIDiffSummary is the facade re-export of reporting.CIDiffSummary.
type CIDiffSummary = reporting.CIDiffSummary

// BaselineFinding is the facade re-export of reporting.BaselineFinding.
type BaselineFinding = reporting.BaselineFinding

// CIDiffResult compares a current evaluation artifact against a baseline
// and returns the structured diff response. The caller is responsible for
// rendering (JSON, text, etc.) via the Renderer pattern.
func CIDiffResult(ctx context.Context, currentPath, baselinePath string, failOnNew bool) (*CIDiffResponse, error) {
	resp, err := reporting.CIDiff(ctx, reporting.CIDiffRequest{
		CurrentPath:  currentPath,
		BaselinePath: baselinePath,
		FailOnNew:    failOnNew,
	}, reporting.CIDiffDeps{
		CurrentLoader:  &infrabaseline.EvaluationLoader{},
		BaselineLoader: &infrabaseline.EvaluationLoader{},
		Clock:          ports.RealClock{},
	})
	if err != nil {
		return nil, fmt.Errorf("run CI diff: %w", err)
	}
	return &resp, nil
}
