// Package monitor implements the 'stave monitor' command for a
// terminal security posture display.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	infraSLA "github.com/sufield/stave/internal/adapters/sla"
	appmon "github.com/sufield/stave/internal/app/monitor"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/report"
)

type options struct {
	HistoryDir string
	SLAFile    string
	Refresh    int
	Format     string
	NoColor    bool
}

// NewCmd constructs the monitor command.
func NewCmd() *cobra.Command {
	opts := &options{
		Refresh: 30,
		Format:  "live",
	}

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Terminal security posture monitor",
		Long: `Display current posture score, top findings, SLA burn rates,
and severity distribution in a single terminal view. Refreshes
automatically at the specified interval.

Formats:
  live    ANSI terminal display with auto-refresh (default)
  json    Single-shot structured output, then exit
  plain   Human-readable text, no ANSI codes

Inputs:
  --history PATH          History directory (required)
  --sla-profile-file PATH SLA policy for burn rate display
  --refresh INT           Refresh interval in seconds (default: 30)

Exit Codes:
  0   Normal exit (q key or signal)
  2   Invalid input
  4   Internal error`,
		Example: `  # Standard monitor
  stave monitor --history ./history

  # With SLA context
  stave monitor --history ./history --sla-profile-file sla.yaml

  # JSON snapshot for scripting
  stave monitor --history ./history --format json

  # Plain text for logging
  stave monitor --history ./history --format plain`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMonitor(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "history directory to monitor (required)")
	cmd.Flags().StringVar(&opts.SLAFile, "sla-profile-file", "", "SLA policy for burn rate display")
	cmd.Flags().IntVar(&opts.Refresh, "refresh", 30, "refresh interval in seconds")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "live", "output format: live | json | plain")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "disable ANSI color codes")

	_ = cmd.MarkFlagRequired("history")

	return cmd
}

func runMonitor(ctx context.Context, stdout, _ io.Writer, opts *options) error {
	loadState := func() (*appmon.State, error) {
		assessments, err := loadAssessments(ctx, opts.HistoryDir)
		if err != nil {
			return nil, err
		}
		if len(assessments) == 0 {
			return nil, fmt.Errorf("no assessment files in %s", opts.HistoryDir)
		}
		chains, _ := ctlyaml.LoadChains("chains")
		var slaDeadlines map[string]float64
		if opts.SLAFile != "" {
			if pol, slaErr := infraSLA.LoadFromFile(opts.SLAFile); slaErr == nil {
				slaDeadlines = map[string]float64{
					"critical": pol.DeadlineHoursFor("critical"),
					"high":     pol.DeadlineHoursFor("high"),
					"medium":   pol.DeadlineHoursFor("medium"),
					"low":      pol.DeadlineHoursFor("low"),
				}
			}
		}
		return appmon.Build(appmon.BuildInput{
			GeneratedAt:    time.Now().UTC().Format("2006-01-02 15:04:05"),
			Assessments:    assessments,
			ChainDefs:      len(chains),
			MaxChainWeight: appscore.ChainMaxWeight(chains),
			SLADeadlines:   slaDeadlines,
		}), nil
	}

	switch opts.Format {
	case "json":
		state, err := loadState()
		if err != nil {
			return &ui.UserError{Err: err}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(state)

	case "plain":
		state, err := loadState()
		if err != nil {
			return &ui.UserError{Err: err}
		}
		appmon.RenderPlain(stdout, state, false)
		return nil

	case "live":
		return runLiveLoop(ctx, stdout, opts, loadState)

	default:
		return &ui.UserError{Err: fmt.Errorf("unknown format %q (valid: live, json, plain)", opts.Format)}
	}
}

func runLiveLoop(ctx context.Context, stdout io.Writer, opts *options, loadState func() (*appmon.State, error)) error {
	// Handle signals for clean exit.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(time.Duration(opts.Refresh) * time.Second)
	defer ticker.Stop()

	// Initial render.
	if err := renderOnce(ctx, stdout, opts, loadState); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sigCh:
			return nil
		case <-ticker.C:
			if err := renderOnce(ctx, stdout, opts, loadState); err != nil {
				// Log error but keep running.
				fmt.Fprintf(stdout, "\nRefresh error: %v\n", err)
			}
		}
	}
}

func renderOnce(_ context.Context, stdout io.Writer, opts *options, loadState func() (*appmon.State, error)) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	appmon.RenderLive(stdout, state, opts.NoColor)
	return nil
}

func loadAssessments(ctx context.Context, dir string) ([]*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	loader := artifact.NewLoader()
	var out []*report.Assessment
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		a, loadErr := loader.Evaluation(ctx, filepath.Join(dir, e.Name()))
		if loadErr != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}
