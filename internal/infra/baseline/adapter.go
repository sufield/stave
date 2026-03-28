package baseline

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/fileout"
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// EvaluationLoader satisfies usecases.EvaluationLoaderPort.
type EvaluationLoader struct{}

// LoadFindings loads an evaluation artifact and extracts baseline-level findings.
func (l *EvaluationLoader) LoadFindings(ctx context.Context, path string) ([]reporting.BaselineFinding, error) {
	loader := &evaljson.Loader{}
	eval, err := loader.LoadEnvelopeFromFile(ctx, fsutil.CleanUserPath(path))
	if err != nil {
		return nil, err
	}
	entries := remediation.BaselineEntriesFromFindings(eval.Findings)
	return entriesToDomain(entries), nil
}

// BaselineLoader satisfies usecases.BaselineLoaderPort.
type BaselineLoader struct{}

// LoadBaseline loads a saved baseline artifact.
func (l *BaselineLoader) LoadBaseline(ctx context.Context, path string) ([]reporting.BaselineFinding, error) {
	loader := &evaljson.Loader{}
	base, err := loader.LoadBaselineFromFile(ctx, fsutil.CleanUserPath(path), kernel.KindBaseline)
	if err != nil {
		return nil, err
	}
	return entriesToDomain(base.Findings), nil
}

// BaselineWriter satisfies usecases.BaselineWriterPort.
type BaselineWriter struct {
	FileOptions fileout.FileOptions
}

// WriteBaseline writes a baseline snapshot to disk.
func (w *BaselineWriter) WriteBaseline(_ context.Context, path string, findings []reporting.BaselineFinding, createdAt time.Time, sourcePath string) error {
	baseline := evaluation.Baseline{
		SchemaVersion:    kernel.SchemaBaseline,
		Kind:             kernel.KindBaseline,
		CreatedAt:        createdAt,
		SourceEvaluation: sourcePath,
		Findings:         domainToEntries(findings),
	}

	f, err := fileout.OpenOutputFile(fsutil.CleanUserPath(path), w.FileOptions)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	return jsonutil.WriteIndented(f, baseline)
}

func entriesToDomain(entries []evaluation.BaselineEntry) []reporting.BaselineFinding {
	out := make([]reporting.BaselineFinding, len(entries))
	for i, e := range entries {
		out[i] = reporting.BaselineFinding{
			ControlID:   string(e.ControlID),
			ControlName: e.ControlName,
			AssetID:     string(e.AssetID),
			AssetType:   string(e.AssetType),
		}
	}
	return out
}

func domainToEntries(findings []reporting.BaselineFinding) []evaluation.BaselineEntry {
	out := make([]evaluation.BaselineEntry, len(findings))
	for i, f := range findings {
		out[i] = evaluation.BaselineEntry{
			ControlID:   kernel.ControlID(f.ControlID),
			ControlName: f.ControlName,
			AssetID:     asset.ID(f.AssetID),
			AssetType:   kernel.AssetType(f.AssetType),
		}
	}
	return out
}
