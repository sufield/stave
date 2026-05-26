package stave

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// LoadAssessment reads an `out.v0.1.json` evaluation output file and
// returns the public [Assessment] view. Useful for tools (and the
// `stave score` CLI) that consume previously-persisted Apply output
// rather than re-running evaluation in-process.
//
// The internal *report.Assessment is converted via
// [FromReportAssessment] so callers in `cmd/` and external library
// users see the same public shape they would from a fresh [Apply]
// call.
func LoadAssessment(_ context.Context, path string) (*Assessment, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read assessment: %w", err)
	}
	var internalAsmt report.Assessment
	if jsonErr := json.Unmarshal(data, &internalAsmt); jsonErr != nil {
		return nil, fmt.Errorf("parse assessment: %w", jsonErr)
	}
	return FromReportAssessment(&internalAsmt), nil
}

// LoadAssessments reads every `*.json` file in `dir` as an evaluation
// output and returns them as a slice. Files that fail to load are
// logged to stderr and skipped — the function returns nil error
// unless the directory itself can't be read, matching the existing
// `stave score --history` semantics that prefer partial results
// over total failure.
//
// Returned slice order is filesystem-walk order. Use
// [SortAssessmentsByTime] if you need chronological ordering.
func LoadAssessments(ctx context.Context, dir string) ([]*Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history directory: %w", err)
	}

	loader := artifacts.NewLoader()
	var out []*Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", entry.Name(), loadErr)
			continue
		}
		out = append(out, FromReportAssessment(a))
	}
	return out, nil
}

// SortAssessmentsByTime stable-sorts assessments by Run.Now ascending,
// preserving directory-load order when two assessments share an
// identical timestamp. The stable sort matters for sequential
// assessments produced inside the same wall-clock second: an
// unstable sort produces non-deterministic trend output run-to-run.
func SortAssessmentsByTime(assessments []*Assessment) {
	slices.SortStableFunc(assessments, func(a, b *Assessment) int {
		switch {
		case a.Run.Now.Before(b.Run.Now):
			return -1
		case b.Run.Now.Before(a.Run.Now):
			return 1
		default:
			return 0
		}
	})
}

// SnapshotID returns the deterministic snapshot identifier callers
// (cmd/score's trend builder) attach to per-assessment rows:
// "snap-YYYYMMDD" derived from Run.Now, or "" when the assessment
// carries no timestamp.
func (a *Assessment) SnapshotID() string {
	if a == nil || a.Run.Now.IsZero() {
		return ""
	}
	return "snap-" + a.Run.Now.Format("20060102")
}

// HasFindings reports whether the assessment carries at least one
// finding. Mirrors [report.Assessment.HasFindings] for the public
// type so callers don't have to len-check the slice themselves.
func (a *Assessment) HasFindings() bool {
	return a != nil && len(a.Findings) > 0
}
