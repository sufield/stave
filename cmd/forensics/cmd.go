// Package forensics implements the 'stave forensics' command for
// multi-snapshot forensic timeline reconstruction.
package forensics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appbisect "github.com/sufield/stave/internal/app/bisect"
	appforensics "github.com/sufield/stave/internal/app/forensics"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	AssetID     string
	HistoryDir  string
	ControlsDir string
	Format      string
	OutPath     string
}

// NewCmd constructs the forensics command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table", ControlsDir: "controls"}

	cmd := &cobra.Command{
		Use:   "forensics",
		Short: "Reconstruct asset-centric forensic timeline from snapshot history",
		Long: `Analyze multiple snapshots to reconstruct a complete timeline of
property changes, control verdict transitions, and chain activations
for a specific asset.

Exit Codes:
  0   Timeline produced
  2   Invalid input
  4   Internal error`,
		Example: `  stave forensics --asset arn:aws:s3:::phi-records --history ./snapshots/
  stave forensics --asset arn:aws:s3:::phi-records --history ./snapshots/ --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runForensics(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.AssetID, "asset", "", "asset ARN to reconstruct timeline for (required)")
	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of snapshot files (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "path to controls directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | markdown")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "write to file instead of stdout")

	_ = cmd.MarkFlagRequired("asset")
	_ = cmd.MarkFlagRequired("history")

	return cmd
}

func runForensics(ctx context.Context, stdout io.Writer, opts *options) error {
	// Load snapshots.
	logger := slog.Default()
	snapshots, err := appbisect.LoadSnapshotDir(
		fsutil.CleanUserPath(opts.HistoryDir),
		fsutil.ReadFileLimited,
		logger,
	)
	if err != nil {
		return fmt.Errorf("load snapshots: %w", err)
	}
	if len(snapshots) == 0 {
		return fmt.Errorf("no snapshots in %s", opts.HistoryDir)
	}

	// Load controls.
	f := compose.DefaultFactories()
	ctlRepo, err := f.NewCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlRepo.LoadControls(ctx, fsutil.CleanUserPath(opts.ControlsDir))
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	// CEL evaluator.
	celEval, err := f.NewCELEvaluator()
	if err != nil {
		return fmt.Errorf("init CEL: %w", err)
	}

	// Build timeline.
	tl, tlErr := appforensics.BuildTimeline(ctx, appforensics.Input{
		AssetID:   opts.AssetID,
		Snapshots: snapshots,
		Controls:  controls,
		CELEval:   celEval,
		Clock:     ports.RealClock{},
		Hasher:    crypto.NewHasher(),
	})
	if tlErr != nil {
		return tlErr
	}

	out := stdout
	if opts.OutPath != "" {
		outFile, createErr := os.Create(opts.OutPath)
		if createErr != nil {
			return fmt.Errorf("create output: %w", createErr)
		}
		defer outFile.Close()
		out = outFile
	}

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(tl)
	default:
		writeTableTimeline(out, tl)
		return nil
	}
}

func writeTableTimeline(w io.Writer, tl *appforensics.Timeline) {
	fmt.Fprintf(w, "FORENSIC TIMELINE — %s\n", tl.AssetID)
	fmt.Fprintf(w, "Period: %s → %s  |  Snapshots: %d  |  Events: %d\n\n",
		tl.Period.From, tl.Period.To, tl.SnapshotsAnalyzed, len(tl.Events))

	for i := range tl.Events {
		if line := tl.Events[i].FormatLine(); line != "" {
			fmt.Fprintln(w, line)
		}
	}

	if len(tl.ExposureWindows) > 0 {
		fmt.Fprintln(w, "\nEXPOSURE WINDOWS")
		fmt.Fprintln(w, strings.Repeat("-", 70))
		for i := range tl.ExposureWindows {
			ew := &tl.ExposureWindows[i]
			fmt.Fprintf(w, "  %-30s  first: %s  duration: %.0f days  %s\n",
				ew.ControlID, ew.FirstFailed[:10], ew.ExposureDays, strings.ToUpper(ew.Status))
		}
	}
}
