package stave

import (
	"bytes"
	"context"
	"fmt"
	"os"

	infrabaseline "github.com/sufield/stave/internal/adapters/baseline"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/platform/fileout"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// BaselineSave captures the findings in an evaluation artifact as a
// baseline file at outputPath and returns the human-readable confirmation
// line. It is the library entry point behind `stave ci baseline save`.
// Failures stay plain (exit 4).
func BaselineSave(ctx context.Context, evaluationPath, outputPath string) ([]byte, error) {
	writer, err := infrabaseline.NewWriter(func(path string) (*os.File, error) {
		return fileout.OpenOutputFile(path, fileout.FileOptions{DirPerms: 0o755})
	})
	if err != nil {
		return nil, fmt.Errorf("wire baseline writer: %w", err)
	}

	resp, err := reporting.BaselineSave(ctx, reporting.BaselineSaveRequest{
		EvaluationPath: evaluationPath,
		OutputPath:     outputPath,
	}, reporting.BaselineSaveDeps{
		Loader: &infrabaseline.EvaluationLoader{},
		Writer: writer,
		Clock:  ports.RealClock{},
	})
	if err != nil {
		return nil, fmt.Errorf("save baseline: %w", err)
	}

	return fmt.Appendf(nil, "Saved baseline: %s (findings=%d)\n", resp.OutputPath, resp.FindingsCount), nil
}

// BaselineCheck compares the findings in an evaluation artifact against a
// saved baseline and renders the new/resolved report as indented JSON. It
// returns the rendered bytes and whether new findings were introduced AND
// failOnNew was set (the caller maps that to exit 3 — the report is still
// rendered). Failures stay plain (exit 4). It is the library entry point
// behind `stave ci baseline check`.
func BaselineCheck(ctx context.Context, evaluationPath, baselinePath string, failOnNew bool) ([]byte, bool, error) {
	resp, err := reporting.BaselineCheck(ctx, reporting.BaselineCheckRequest{
		EvaluationPath: evaluationPath,
		BaselinePath:   baselinePath,
		FailOnNew:      failOnNew,
	}, reporting.BaselineCheckDeps{
		EvalLoader:     &infrabaseline.EvaluationLoader{},
		BaselineLoader: &infrabaseline.Loader{},
		Clock:          ports.RealClock{},
	})
	if err != nil {
		return nil, false, fmt.Errorf("check baseline: %w", err)
	}

	var buf bytes.Buffer
	if err := jsonutil.WriteIndented(&buf, resp); err != nil {
		return nil, false, fmt.Errorf("write output: %w", err)
	}
	return buf.Bytes(), failOnNew && resp.HasNew, nil
}
