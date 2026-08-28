package diagnose

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/cel"
	apptrace "github.com/sufield/stave/internal/app/diagnose/trace"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewTraceCmd constructs the trace command.
func NewTraceCmd(newCtlRepo compose.CtlRepoFactory, newSnapshotRepo compose.SnapshotRepoFactory) *cobra.Command {
	var (
		controlID   string
		controlsDir string
		observation string
		assetID     string
		format      string
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
    --format json

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example:       `  stave trace --controls controls/s3 --observation observations/snap.json --control CTL.S3.PUBLIC.001 --asset-id my-bucket`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, fmtErr := compose.ResolveFormatValue(format)
			if fmtErr != nil {
				return fmt.Errorf("resolve format: %w", fmtErr)
			}

			ctx := cmd.Context()
			cleanCtlDir := fsutil.CleanUserPath(strings.TrimSpace(controlsDir))
			cleanObsPath := fsutil.CleanUserPath(strings.TrimSpace(observation))
			ctlID, err := kernel.NewControlID(strings.TrimSpace(controlID))
			if err != nil {
				return fmt.Errorf("invalid control ID %q: %w", controlID, err)
			}

			// Load control via factory
			control, err := loadTraceControl(ctx, newCtlRepo, cleanCtlDir, ctlID)
			if err != nil {
				return err
			}

			// Load snapshot via factory
			snapshot, err := loadTraceSnapshot(ctx, newSnapshotRepo, cleanObsPath)
			if err != nil {
				return err
			}

			tracer := &apptrace.PolicyTracer{Tracer: cel.Tracer{}}
			result, err := tracer.Trace(&apptrace.TraceRequest{
				Control:    control,
				Snapshot:   snapshot,
				TargetID:   asset.ID(strings.TrimSpace(assetID)),
				SourcePath: cleanObsPath,
			})
			if err != nil {
				return fmt.Errorf("trace predicate: %w", err)
			}

			w := cliflags.GetGlobalFlags(cmd).ResolveStdout(cmd.OutOrStdout())
			renderer, err := NewTraceRenderer(fmtValue)
			if err != nil {
				return err
			}
			return renderer.Render(w, result)
		},
	}

	cmd.Flags().StringVar(&controlID, "control", "", "Control ID to trace (required)")
	cmd.Flags().StringVarP(&controlsDir, "controls", "i", cliflags.DefaultControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVar(&observation, "observation", "", "Path to single observation JSON file (required)")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "Asset ID to trace against (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	_ = cmd.MarkFlagRequired("control")
	_ = cmd.MarkFlagRequired("observation")
	_ = cmd.MarkFlagRequired("asset-id")

	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))

	return cmd
}

// loadTraceControl loads a specific control by ID via factory.
func loadTraceControl(ctx context.Context, newCtlRepo compose.CtlRepoFactory, dir string, id kernel.ControlID) (policy.ControlDefinition, error) {
	repo, err := newCtlRepo()
	if err != nil {
		return policy.ControlDefinition{}, err
	}
	ctl, err := compose.FindControlByID(ctx, repo, dir, id)
	if err != nil {
		return policy.ControlDefinition{}, ui.WithNextCommand(err,
			fmt.Sprintf("stave explain --controls %s <control-id>", dir))
	}
	return ctl, nil
}

// loadTraceSnapshot loads a single snapshot file via factory.
func loadTraceSnapshot(ctx context.Context, newSnapshotRepo compose.SnapshotRepoFactory, path string) (*asset.Snapshot, error) {
	obsLoader, err := newSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	// #nosec G304 -- path is an explicit CLI-provided local file path.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open observation file: %w", err)
	}
	// Close errors on a read-only file mostly indicate filesystem
	// instability (lazy unmount, EIO). Log at Debug so they surface
	// in verbose runs without obscuring the load result.
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			slog.Debug("close observation file", "path", path, "error", closeErr)
		}
	}()

	snapshot, err := obsLoader.LoadSnapshotFromReader(ctx, f, path)
	if err != nil {
		return nil, fmt.Errorf("load observation: %w", err)
	}
	return &snapshot, nil
}
