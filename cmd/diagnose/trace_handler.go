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

type traceFlagsType struct {
	controlID   string
	controlsDir string
	observation string
	assetID     string
	format      string
	quiet       bool
}

// NewTraceCmd constructs the trace command with closure-scoped flags.
func NewTraceCmd() *cobra.Command {
	var flags traceFlagsType

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
			return runTrace(cmd, &flags)
		},
	}

	cmd.Flags().StringVar(&flags.controlID, "control", "", "Control ID to trace (required)")
	cmd.Flags().StringVarP(&flags.controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVar(&flags.observation, "observation", "", "Path to single observation JSON file (required)")
	cmd.Flags().StringVar(&flags.assetID, "asset-id", "", "Asset ID to trace against (required)")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&flags.quiet, "quiet", cmdutil.ResolveQuietDefault(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	_ = cmd.MarkFlagRequired("control")
	_ = cmd.MarkFlagRequired("observation")
	_ = cmd.MarkFlagRequired("asset-id")

	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

func runTrace(cmd *cobra.Command, flags *traceFlagsType) error {
	if flags.quiet {
		return nil
	}
	format, err := cmdutil.ResolveFormatValue(cmd, flags.format)
	if err != nil {
		return err
	}

	ctx := cmdutil.CommandContext(cmd)
	ctlDir := fsutil.CleanUserPath(strings.TrimSpace(flags.controlsDir))
	control, err := loadTraceControl(ctx, ctlDir, strings.TrimSpace(flags.controlID))
	if err != nil {
		return err
	}
	observationPath := fsutil.CleanUserPath(strings.TrimSpace(flags.observation))
	snapshot, err := loadTraceSnapshot(ctx, observationPath)
	if err != nil {
		return err
	}
	assetID := strings.TrimSpace(flags.assetID)
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

func loadTraceControl(ctx context.Context, controlsDir, controlID string) (*policy.ControlDefinition, error) {
	ctl, err := cmdutil.LoadControlByID(ctx, controlsDir, controlID)
	if err != nil {
		return nil, ui.WithNextCommand(err,
			fmt.Sprintf("stave explain --controls %s <control-id>", controlsDir))
	}
	return ctl, nil
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
