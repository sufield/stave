package trend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/core/report"
)

func runTrend(ctx context.Context, w io.Writer, opts *trendOptions) error {
	if opts.HistoryDir == "" && opts.Files == "" {
		return errors.New("either --history or --files is required")
	}

	assessments, err := loadAssessments(ctx, opts)
	if err != nil {
		return err
	}

	if len(assessments) < opts.MinRuns {
		return fmt.Errorf("trend requires at least %d assessment files (found %d)", opts.MinRuns, len(assessments))
	}

	// Sort by timestamp.
	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})

	// Apply window limit.
	if opts.Window > 0 && len(assessments) > opts.Window {
		assessments = assessments[len(assessments)-opts.Window:]
	}

	// Compute per-run metrics.
	runs := make([]RunMetrics, len(assessments))
	for i, a := range assessments {
		var prev *RunMetrics
		if i > 0 {
			prev = &runs[i-1]
		}
		runs[i] = computeRunMetrics(a, prev)
		runs[i].FilePath = "" // not tracked in this path
	}

	// Compute MTTR.
	mttr := computeMTTR(assessments)

	// Compute velocity.
	velocity := computeVelocity(runs, 5)

	// Compute projection.
	projection := computeProjection(runs, velocity)

	// Build report.
	trendReport := TrendReport{
		GeneratedAt: time.Now().UTC(),
		Period: Period{
			Start:    assessments[0].Run.Now,
			End:      assessments[len(assessments)-1].Run.Now,
			RunCount: len(assessments),
		},
		Summary: TrendSummary{
			FirstViolationRate:  runs[0].ViolationRate,
			LatestViolationRate: runs[len(runs)-1].ViolationRate,
		},
		Runs:       runs,
		MTTR:       mttr,
		Velocity:   velocity,
		Projection: projection,
	}

	// Compute summary direction.
	if trendReport.Summary.FirstViolationRate > 0 {
		change := (trendReport.Summary.LatestViolationRate - trendReport.Summary.FirstViolationRate) /
			trendReport.Summary.FirstViolationRate * 100
		trendReport.Summary.NetChangePercent = change
	}
	trendReport.Summary.Direction = velocity.Direction

	// Write output.
	out := w
	if opts.Out != "" {
		f, fileErr := os.Create(opts.Out)
		if fileErr != nil {
			return fmt.Errorf("create output file: %w", fileErr)
		}
		defer f.Close()
		out = f
	}

	switch opts.Format {
	case "json":
		return renderTrendJSON(out, &trendReport)
	default:
		return renderTrendTable(out, &trendReport)
	}
}

func loadAssessments(ctx context.Context, opts *trendOptions) ([]*report.Assessment, error) {
	loader := artifact.NewLoader()

	if opts.Files != "" {
		paths := strings.Split(opts.Files, ",")
		var assessments []*report.Assessment
		for _, p := range paths {
			p = strings.TrimSpace(p)
			a, err := loader.Evaluation(ctx, p)
			if err != nil {
				return nil, fmt.Errorf("load %s: %w", p, err)
			}
			assessments = append(assessments, a)
		}
		return assessments, nil
	}

	// Walk history directory.
	entries, err := os.ReadDir(opts.HistoryDir)
	if err != nil {
		return nil, fmt.Errorf("read history directory: %w", err)
	}

	var assessments []*report.Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(opts.HistoryDir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", entry.Name(), loadErr)
			continue
		}
		assessments = append(assessments, a)
	}

	return assessments, nil
}
