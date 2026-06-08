package stave

import (
	"bytes"
	"context"
	"fmt"

	infrabaseline "github.com/sufield/stave/internal/adapters/baseline"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// CIDiff compares a current evaluation artifact against a baseline
// evaluation and renders the newly-introduced and resolved findings as
// indented JSON. It returns the rendered bytes and whether new findings
// were introduced AND failOnNew was set (the caller maps that to exit 3 —
// the diff is still rendered). All failures stay plain (exit 4). It is the
// library entry point behind `stave ci diff`.
func CIDiff(ctx context.Context, currentPath, baselinePath string, failOnNew bool) ([]byte, bool, error) {
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
		return nil, false, fmt.Errorf("run CI diff: %w", err)
	}

	var buf bytes.Buffer
	if err := jsonutil.WriteIndented(&buf, resp); err != nil {
		return nil, false, fmt.Errorf("write output: %w", err)
	}
	return buf.Bytes(), failOnNew && resp.HasNew, nil
}
