package diagnose

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/trace"
)

// TraceRequest defines the parameters for tracing a predicate evaluation.
type TraceRequest struct {
	ControlID       string
	ControlsDir     string
	ObservationPath string
	AssetID         string
	Format          ui.OutputFormat
	Quiet           bool
	Stdout          io.Writer
}

// TraceRunner orchestrates evaluation trace generation for a specific asset.
type TraceRunner struct {
	Provider *compose.Provider
}

// NewTraceRunner creates a runner with the provided dependency provider.
func NewTraceRunner(p *compose.Provider) *TraceRunner {
	return &TraceRunner{Provider: p}
}

// Run executes the trace workflow.
func (r *TraceRunner) Run(ctx context.Context, req TraceRequest) error {
	if req.Quiet {
		return nil
	}

	control, err := r.loadControl(ctx, req.ControlsDir, req.ControlID)
	if err != nil {
		return err
	}

	snapshot, err := r.loadSnapshot(ctx, req.ObservationPath)
	if err != nil {
		return err
	}

	found, err := findTraceAsset(snapshot, req.AssetID, req.ObservationPath)
	if err != nil {
		return err
	}

	result := buildTraceResult(&control, found, snapshot)

	if req.Format.IsJSON() {
		return trace.WriteJSON(req.Stdout, result)
	}
	return trace.WriteText(req.Stdout, result)
}

func (r *TraceRunner) loadControl(ctx context.Context, dir, id string) (policy.ControlDefinition, error) {
	ctl, err := compose.LoadControlByID(ctx, r.Provider, dir, id)
	if err != nil {
		return policy.ControlDefinition{}, ui.WithNextCommand(err,
			fmt.Sprintf("stave explain --controls %s <control-id>", dir))
	}
	return ctl, nil
}

func (r *TraceRunner) loadSnapshot(ctx context.Context, path string) (*asset.Snapshot, error) {
	obsLoader, err := r.Provider.NewSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	// #nosec G304 -- path is an explicit CLI-provided local file path.
	f, err := os.Open(fsutil.CleanUserPath(path))
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

func findTraceAsset(snapshot *asset.Snapshot, assetID, path string) (*asset.Asset, error) {
	for i := range snapshot.Assets {
		if snapshot.Assets[i].ID.String() == assetID {
			return &snapshot.Assets[i], nil
		}
	}
	available := make([]string, 0, len(snapshot.Assets))
	for _, a := range snapshot.Assets {
		available = append(available, a.ID.String())
	}
	slices.Sort(available)
	return nil, fmt.Errorf("asset %q not found in %s\nAvailable assets: %s",
		assetID, path, strings.Join(available, ", "))
}

func buildTraceResult(ctl *policy.ControlDefinition, a *asset.Asset, snapshot *asset.Snapshot) *trace.Result {
	evalCtx := policy.NewAssetEvalContext(*a, ctl.Params, snapshot.Identities...)
	evalCtx.PredicateParser = ctlyaml.ParsePredicate
	root := trace.TracePredicate(ctl.UnsafePredicate, evalCtx)
	return &trace.Result{
		ControlID:   kernel.ControlID(ctl.ID),
		AssetID:     a.ID,
		Properties:  a.Properties,
		Params:      ctl.Params,
		Root:        root,
		FinalResult: root.Result,
	}
}

// --- CLI bridge ---

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
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}

			runner := NewTraceRunner(p)
			return runner.Run(cmd.Context(), TraceRequest{
				ControlID:       strings.TrimSpace(controlID),
				ControlsDir:     fsutil.CleanUserPath(strings.TrimSpace(controlsDir)),
				ObservationPath: fsutil.CleanUserPath(strings.TrimSpace(observation)),
				AssetID:         strings.TrimSpace(assetID),
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
	cmd.Flags().BoolVar(&quiet, "quiet", projconfig.Global().Quiet(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	_ = cmd.MarkFlagRequired("control")
	_ = cmd.MarkFlagRequired("observation")
	_ = cmd.MarkFlagRequired("asset-id")

	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}
