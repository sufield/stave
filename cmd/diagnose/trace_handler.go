package diagnose

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/trace"
)

var (
	traceControlID   string
	traceControlsDir string
	traceObservation string
	traceAssetID     string
	traceFormat      string
	traceQuiet       bool
)

var TraceCmd = &cobra.Command{
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
	RunE:          runTrace,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	TraceCmd.Flags().StringVar(&traceControlID, "control", "", "Control ID to trace (required)")
	TraceCmd.Flags().StringVarP(&traceControlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	TraceCmd.Flags().StringVar(&traceObservation, "observation", "", "Path to single observation JSON file (required)")
	TraceCmd.Flags().StringVar(&traceAssetID, "asset-id", "", "Asset ID to trace against (required)")
	TraceCmd.Flags().StringVarP(&traceFormat, "format", "f", "text", "Output format: text or json")
	TraceCmd.Flags().BoolVar(&traceQuiet, "quiet", cmdutil.ResolveQuietDefault(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	_ = TraceCmd.MarkFlagRequired("control")
	_ = TraceCmd.MarkFlagRequired("observation")
	_ = TraceCmd.MarkFlagRequired("asset-id")

	_ = TraceCmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
}

func runTrace(cmd *cobra.Command, _ []string) error {
	if traceQuiet {
		return nil
	}
	format, err := resolveTraceOutputFormat(cmd)
	if err != nil {
		return err
	}

	ctx := cmdutil.CommandContext(cmd)
	ctlDir := fsutil.CleanUserPath(strings.TrimSpace(traceControlsDir))
	control, err := loadTraceControl(ctx, ctlDir, strings.TrimSpace(traceControlID))
	if err != nil {
		return err
	}
	observationPath := fsutil.CleanUserPath(strings.TrimSpace(traceObservation))
	snapshot, err := loadTraceSnapshot(ctx, observationPath)
	if err != nil {
		return err
	}
	assetID := strings.TrimSpace(traceAssetID)
	found, err := findTraceAsset(snapshot, assetID, observationPath)
	if err != nil {
		return err
	}
	result := buildTraceResult(control, found, snapshot)

	// Render
	w := cmd.OutOrStdout()
	if format.IsJSON() {
		return trace.WriteJSON(w, result)
	}
	return trace.WriteText(w, result)
}

func resolveTraceOutputFormat(cmd *cobra.Command) (ui.OutputFormat, error) {
	return cmdutil.ResolveFormatValue(cmd, traceFormat)
}

func loadTraceControl(ctx context.Context, controlsDir, controlID string) (*policy.ControlDefinition, error) {
	loader, err := cmdutil.NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := loader.LoadControls(ctx, controlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	for i := range controls {
		if controls[i].ID.String() == controlID {
			return &controls[i], nil
		}
	}
	return nil, ui.WithNextCommand(
		fmt.Errorf("control %q not found in %s", controlID, controlsDir),
		fmt.Sprintf("stave explain --controls %s <control-id>", controlsDir),
	)
}

func loadTraceSnapshot(ctx context.Context, observationPath string) (*asset.Snapshot, error) {
	obsLoader, err := cmdutil.NewSnapshotObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	// #nosec G304 -- observationPath is an explicit CLI-provided local file path.
	f, err := os.Open(observationPath)
	if err != nil {
		return nil, fmt.Errorf("open observation file: %w", err)
	}
	defer f.Close()

	snapshot, err := obsLoader.LoadSnapshotFromReader(ctx, f, observationPath)
	if err != nil {
		return nil, fmt.Errorf("load observation: %w", err)
	}
	return &snapshot, nil
}

func findTraceAsset(snapshot *asset.Snapshot, assetID, observationPath string) (*asset.Asset, error) {
	for i := range snapshot.Assets {
		if snapshot.Assets[i].ID.String() == assetID {
			return &snapshot.Assets[i], nil
		}
	}
	available := make([]string, 0, len(snapshot.Assets))
	for _, r := range snapshot.Assets {
		available = append(available, r.ID.String())
	}
	return nil, fmt.Errorf("asset %q not found in %s\nAvailable assets: %s",
		assetID, observationPath, strings.Join(available, ", "))
}

func buildTraceResult(ctl *policy.ControlDefinition, a *asset.Asset, snapshot *asset.Snapshot) *trace.TraceResult {
	ctx := policy.NewAssetEvalContextWithIdentities(*a, policy.ControlParams(ctl.Params), snapshot.Identities)
	ctx.PredicateParser = ctlyaml.YAMLPredicateParser
	root := trace.TracePredicate(ctl.UnsafePredicate, ctx)
	return &trace.TraceResult{
		ControlID:   kernel.ControlID(ctl.ID),
		AssetID:     a.ID,
		Properties:  a.Properties,
		Params:      ctl.Params,
		Root:        root,
		FinalResult: root.Result,
	}
}
