package diagnose

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	apptrace "github.com/sufield/stave/internal/app/diagnose/trace"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// NewTraceCmd constructs the trace command.
func NewTraceCmd(p *compose.Provider) *cobra.Command {
	var (
		controlID   string
		controlsDir string
		observation string
		assetID     string
		format      string
		quiet       bool
	)

	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace predicate evaluation for a single control against a single asset",
		Long: `Trace walks a control's unsafe_predicate clause by clause against a
single asset and prints a detailed evaluation log — field value,
operator, comparison value, and PASS/FAIL — for every clause.

Use this when you get unexpected evaluation results and want to
understand exactly why a control did or did not match.

Examples:
  stave trace --control CTL.S3.PUBLIC.001 \
    --observation observations/2026-01-11T000000Z.json \
    --asset-id res:aws:s3:bucket:public-bucket

  stave trace --control CTL.S3.ENCRYPT.001 \
    --observation observations/2026-01-11T000000Z.json \
    --asset-id res:aws:s3:bucket:public-bucket \
    --format json` + metadata.OfflineHelpSuffix,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("quiet") {
				quiet = cmdctx.EvaluatorFromCmd(cmd).Quiet()
			}
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}

			ctx := cmd.Context()
			cleanCtlDir := fsutil.CleanUserPath(strings.TrimSpace(controlsDir))
			cleanObsPath := fsutil.CleanUserPath(strings.TrimSpace(observation))
			trimmedCtlID := strings.TrimSpace(controlID)

			// Load control via Provider
			control, err := loadTraceControl(ctx, p, cleanCtlDir, trimmedCtlID)
			if err != nil {
				return err
			}

			// Load snapshot via Provider
			snapshot, err := loadTraceSnapshot(ctx, p, cleanObsPath)
			if err != nil {
				return err
			}

			// Delegate to internal runner
			runner := &apptrace.Runner{}
			return runner.Run(ctx, apptrace.Config{
				Control:         control,
				Snapshot:        snapshot,
				AssetID:         strings.TrimSpace(assetID),
				ObservationPath: cleanObsPath,
				Format:          fmtValue,
				Quiet:           quiet || cmdutil.GetGlobalFlags(cmd).Quiet,
				Stdout:          cmd.OutOrStdout(),
			})
		},
	}

	cmd.Flags().StringVar(&controlID, "control", "", "Control ID to trace (required)")
	cmd.Flags().StringVarP(&controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVar(&observation, "observation", "", "Path to single observation JSON file (required)")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "Asset ID to trace against (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&quiet, "quiet", false, cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	_ = cmd.MarkFlagRequired("control")
	_ = cmd.MarkFlagRequired("observation")
	_ = cmd.MarkFlagRequired("asset-id")

	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

// loadTraceControl loads a specific control by ID via Provider.
func loadTraceControl(ctx context.Context, p *compose.Provider, dir, id string) (policy.ControlDefinition, error) {
	ctl, err := compose.LoadControlByID(ctx, p, dir, id)
	if err != nil {
		return policy.ControlDefinition{}, ui.WithNextCommand(err,
			fmt.Sprintf("stave explain --controls %s <control-id>", dir))
	}
	return ctl, nil
}

// loadTraceSnapshot loads a single snapshot file via Provider.
func loadTraceSnapshot(ctx context.Context, p *compose.Provider, path string) (*asset.Snapshot, error) {
	obsLoader, err := p.NewSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	// #nosec G304 -- path is an explicit CLI-provided local file path.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open observation file: %w", err)
	}
	defer f.Close()

	snapshot, err := obsLoader.LoadSnapshotFromReader(ctx, f, path)
	if err != nil {
		return nil, fmt.Errorf("load observation: %w", err)
	}
	return &snapshot, nil
}
