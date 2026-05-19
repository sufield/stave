// Package coverage implements the 'stave coverage' command for
// observation field coverage gap analysis against control predicates.
package coverage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/app/fieldcov"
	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	SnapshotPath string
	ControlsDir  string
	Format       string
	OutFile      string
}

// NewCmd constructs the coverage command.
func NewCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	opts := &options{
		ControlsDir: "controls",
		Format:      "table",
	}

	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Analyze observation field coverage against control predicates",
		Long: `Analyze which controls can evaluate against a snapshot by checking
whether all fields referenced in control predicates are present in
the snapshot's asset properties.

Controls are classified as:
  EVALUABLE    All referenced fields present in snapshot
  INCOMPLETE   Some fields missing — INCOMPLETE verdict expected
  SILENT_RISK  Missing fields could produce false PASS verdicts
  NO_ASSETS    No assets of the required type in snapshot

Inputs:
  --snapshot PATH     Path to observation snapshot JSON (required)
  --controls PATH     Path to controls directory (default: controls)
  --format STRING     Output format: table (default) | json
  --out PATH          Write to file instead of stdout

Exit Codes:
  0   No silent risk controls
  2   Invalid input
  3   Silent risk controls detected`,
		Example: `  # Analyze coverage against snapshot
  stave coverage --snapshot snapshot.json

  # JSON output for automation
  stave coverage --snapshot snapshot.json --format json

  # Check before assessment
  stave coverage --snapshot snapshot.json && stave apply --snapshot snapshot.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCoverage(cmd.Context(), cmd.OutOrStdout(), opts, newCtlRepo)
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "path to observation snapshot JSON (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "path to controls directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file instead of stdout")

	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

func runCoverage(ctx context.Context, stdout io.Writer, opts *options, newCtlRepo compose.CtlRepoFactory) error {
	// Load snapshot.
	snapshots, err := observations.LoadBundle(opts.SnapshotPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load snapshot: %w", err)}
	}
	if len(snapshots) == 0 {
		return &ui.UserError{Err: fmt.Errorf("no snapshots in %s", opts.SnapshotPath)}
	}

	// Load controls.
	repo, err := newCtlRepo()
	if err != nil {
		return fmt.Errorf("init control loader: %w", err)
	}
	controls, err := repo.LoadControls(ctx, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	report := fieldcov.Analyze(fieldcov.AnalyzeInput{
		SnapshotPath: opts.SnapshotPath,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Controls:     controls,
		Snapshots:    snapshots,
	})

	renderer, rendErr := NewRenderer(opts.Format)
	if rendErr != nil {
		return &ui.UserError{Err: rendErr}
	}
	if writeErr := cmdutil.WriteTo(stdout, opts.OutFile, func(w io.Writer) error {
		return renderer.Render(w, report)
	}); writeErr != nil {
		return writeErr
	}

	if report.Summary.SilentRisk > 0 {
		return ui.ErrViolationsFound
	}
	return nil
}
