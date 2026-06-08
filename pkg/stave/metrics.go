package stave

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appmetrics "github.com/sufield/stave/internal/app/metrics"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// RenderMetrics loads the latest assessment from a history directory and
// renders the Prometheus text-format scrape body — posture score,
// findings by severity, SLA burn rates, chain activations, and per-team
// metrics. It is the library entry point behind `stave metrics`.
func RenderMetrics(ctx context.Context, historyDir string) ([]byte, error) {
	latest, err := loadLatestAssessment(ctx, historyDir)
	if err != nil {
		return nil, fmt.Errorf("load history: %w", err)
	}

	// Compute posture score from violation rate.
	var postureScore float64
	if latest.Summary.TotalAssets > 0 {
		postureScore = (1.0 - float64(latest.Summary.Violations)/float64(latest.Summary.TotalAssets)) * 100
	} else {
		postureScore = 100
	}

	// Group findings by team from OwnerTeamID (populated by
	// `stave apply --team-manifest`).
	teamFindings := remediation.FindingSet(latest.Findings).GroupByOwner()

	input := appmetrics.Input{
		Assessment:   latest,
		PostureScore: postureScore,
		TeamFindings: teamFindings,
	}

	var buf bytes.Buffer
	appmetrics.Write(&buf, input)
	return buf.Bytes(), nil
}

// loadLatestAssessment scans dir for assessment JSON files and returns
// the one with the newest run timestamp. Unreadable files are skipped.
func loadLatestAssessment(ctx context.Context, dir string) (*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	loader := artifact.NewLoader()
	var latest *report.Assessment

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			continue
		}
		if latest == nil || a.Run.Now.After(latest.Run.Now) {
			latest = a
		}
	}

	if latest == nil {
		return nil, fmt.Errorf("no assessment files found in %s", dir)
	}
	return latest, nil
}
