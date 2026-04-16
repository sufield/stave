// Package metrics implements the 'stave metrics' command for
// Prometheus text format metric export.
package metrics

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appmetrics "github.com/sufield/stave/internal/app/metrics"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

type options struct {
	HistoryDir string
	OutPath    string
}

// NewCmd constructs the metrics command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Write Prometheus scrape file for node_exporter",
		Long: `Produce a stable Prometheus text format metrics file covering
posture score, findings by severity, SLA burn rates, chain
activations, and per-team metrics.

Designed for the node_exporter textfile collector. Run on a
schedule via cron to maintain continuous monitoring.

Inputs:
  --history DIR         Directory of assessment JSON files (required)
  --out PATH            Output .prom file path (required)

Exit Codes:
  0   Metrics written
  2   Invalid input`,
		Example: `  stave metrics --history ./history --out /var/lib/node_exporter/stave.prom
  stave metrics --history ./history --out stave.prom`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of assessment JSON files (required)")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "output .prom file path (required)")
	_ = cmd.MarkFlagRequired("history")
	_ = cmd.MarkFlagRequired("out")

	return cmd
}

func run(ctx context.Context, stdout io.Writer, opts *options) error {
	// Load latest assessment from history.
	latest, err := loadLatestAssessment(ctx, opts.HistoryDir)
	if err != nil {
		return fmt.Errorf("load history: %w", err)
	}

	// Compute posture score from violation rate.
	var postureScore float64
	if latest.Summary.TotalAssets > 0 {
		postureScore = (1.0 - float64(latest.Summary.Violations)/float64(latest.Summary.TotalAssets)) * 100
	} else {
		postureScore = 100
	}

	// Group findings by team from OwnerTeamID (populated by stave apply --team-manifest).
	teamFindings := make(map[string][]remediation.Finding)
	for i := range latest.Findings {
		f := &latest.Findings[i]
		if f.OwnerTeamID != "" {
			teamFindings[f.OwnerTeamID] = append(teamFindings[f.OwnerTeamID], *f)
		}
	}
	if len(teamFindings) == 0 {
		teamFindings = nil
	}

	input := appmetrics.Input{
		Assessment:   latest,
		PostureScore: postureScore,
		TeamFindings: teamFindings,
	}

	// Write to file.
	f, err := os.Create(opts.OutPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()

	appmetrics.Write(f, input)

	fmt.Fprintf(stdout, "Wrote metrics to %s\n", opts.OutPath)
	return nil
}

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
