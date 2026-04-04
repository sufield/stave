package diagnose

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	promptout "github.com/sufield/stave/internal/adapters/output/prompt"
	diagprompt "github.com/sufield/stave/internal/app/diagnose/prompt"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// --- CLI bridge ---

// NewPromptCmd constructs the prompt command group.
func NewPromptCmd(newCtlRepo compose.CtlRepoFactory, loadSnapshots compose.SnapshotLoader) *cobra.Command {
	promptCmd := &cobra.Command{
		Use:   "prompt",
		Short: "Generate LLM prompts from evaluation results",
		Long:  "Grouped prompt generation commands: from-finding." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	promptCmd.AddCommand(newPromptFromFindingCmd(newCtlRepo, loadSnapshots))

	return promptCmd
}

func newPromptFromFindingCmd(newCtlRepo compose.CtlRepoFactory, loadSnapshots compose.SnapshotLoader) *cobra.Command {
	var (
		evalFile    string
		assetID     string
		controlsDir string
		obsDir      string
		format      string
	)

	cmd := &cobra.Command{
		Use:   "from-finding",
		Short: "Generate an LLM prompt from evaluation findings for a specific asset",
		Long: `From-finding reads evaluation output, loads control definitions and
(optionally) observation snapshots, and generates a rich Markdown prompt ready
for pasting into an AI assistant.

Purpose: Automate the creation of LLM prompts with full finding context —
evidence, control YAML, asset properties — so AI-assisted analysis
starts from complete information.

Inputs:
  --evaluation-file   Path to evaluation JSON output (required)
  --asset-id       Asset ID to filter findings (required)
  --controls        Directory containing YAML control definitions
  --observations      Optional: directory containing observation snapshots

Outputs:
  stdout              Markdown prompt (default) or JSON (--format json)
  stderr              Clipboard hint (pipe to pbcopy/xclip)

Exit Codes:
  0   - Prompt generated successfully
  2   - Invalid input or no findings matched

Examples:
  # Generate a prompt for a specific asset
  stave prompt from-finding \
    --evaluation-file evaluation.json \
    --asset-id my-bucket \
    --controls ./controls/s3

  # Include asset properties from observations
  stave prompt from-finding \
    --evaluation-file evaluation.json \
    --asset-id my-bucket \
    --controls ./controls/s3 \
    --observations ./observations

  # JSON output for scripting
  stave prompt from-finding \
    --evaluation-file evaluation.json \
    --asset-id my-bucket \
    --controls ./controls/s3 \
    --format json

  # Copy to clipboard (macOS)
  stave prompt from-finding \
    --evaluation-file evaluation.json \
    --asset-id my-bucket \
    --controls ./controls/s3 | pbcopy` + metadata.OfflineHelpSuffix,
		Example:       `  stave prompt from-finding --evaluation-file eval.json --asset-id my-bucket --controls controls/s3 --observations observations`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPromptFromFinding(cmd, promptFromFindingOpts{
				evalFile:      evalFile,
				assetID:       assetID,
				controlsDir:   controlsDir,
				obsDir:        obsDir,
				format:        format,
				newCtlRepo:    newCtlRepo,
				loadSnapshots: loadSnapshots,
			})
		},
	}

	cmd.Flags().StringVar(&evalFile, "evaluation-file", "", "Path to evaluation JSON output (required)")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "Asset ID to filter findings (required)")
	cmd.Flags().StringVarP(&controlsDir, "controls", "i", cliflags.DefaultControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVarP(&obsDir, "observations", "o", "", "Path to observation snapshots directory (optional)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	_ = cmd.MarkFlagRequired("evaluation-file")
	_ = cmd.MarkFlagRequired("asset-id")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))

	return cmd
}

// promptFromFindingOpts holds the resolved inputs for prompt generation.
type promptFromFindingOpts struct {
	evalFile      string
	assetID       string
	controlsDir   string
	obsDir        string
	format        string
	newCtlRepo    compose.CtlRepoFactory
	loadSnapshots compose.SnapshotLoader
}

// runPromptFromFinding executes the prompt-from-finding workflow.
func runPromptFromFinding(cmd *cobra.Command, opts promptFromFindingOpts) error {
	fmtValue, fmtErr := compose.ResolveFormatValue(cmd, opts.format)
	if fmtErr != nil {
		return fmtErr
	}

	ctx := cmd.Context()

	ctlByID, err := loadControlsMap(ctx, opts.newCtlRepo, fsutil.CleanUserPath(opts.controlsDir))
	if err != nil {
		return err
	}

	var assetPropsJSON string
	cleanObsDir := fsutil.CleanUserPath(opts.obsDir)
	if cleanObsDir != "" {
		assetPropsJSON, err = loadAssetProperties(ctx, opts.loadSnapshots, cleanObsDir, asset.ID(strings.TrimSpace(opts.assetID)))
		if err != nil {
			return err
		}
	}

	dctx := diagprompt.DiagnosticContext{
		ControlsByID:   ctlByID,
		AssetPropsJSON: assetPropsJSON,
		LoadEval: func(path string) (*evaluation.Result, error) {
			return (&evaljson.Loader{}).LoadFromFile(path)
		},
		BuildPrompt: buildPromptAdapter,
	}

	runner := diagprompt.NewRunner(dctx)
	out, err := runner.Run(ctx, diagprompt.Config{
		EvalFile: fsutil.CleanUserPath(opts.evalFile),
		AssetID:  strings.TrimSpace(opts.assetID),
	})
	if err != nil {
		return err
	}
	return diagprompt.WriteOutput(cmd.OutOrStdout(), cmd.ErrOrStderr(), out, fmtValue, cliflags.GetGlobalFlags(cmd).Quiet)
}

// buildPromptAdapter bridges the app-layer BuildFunc contract to the
// adapters/output/prompt implementation.
func buildPromptAdapter(
	assetID string,
	controlsByID map[kernel.ControlID]*policy.ControlDefinition,
	assetPropsJSON string,
	matched []evaluation.Finding,
) diagprompt.Output {
	builder := &promptout.Builder{
		AssetID:        assetID,
		ControlsByID:   controlsByID,
		AssetPropsJSON: assetPropsJSON,
	}
	data := builder.Build(matched)
	rendered := promptout.RenderPrompt(data)

	findingIDs := make([]kernel.ControlID, len(data.Findings))
	for i, f := range data.Findings {
		findingIDs[i] = f.ControlID
	}
	return diagprompt.Output{
		Rendered:   rendered,
		FindingIDs: findingIDs,
		AssetID:    data.AssetID,
	}
}

// loadControlsMap loads control definitions and indexes them by ID.
func loadControlsMap(ctx context.Context, newCtlRepo compose.CtlRepoFactory, dir string) (map[kernel.ControlID]*policy.ControlDefinition, error) {
	repo, err := newCtlRepo()
	if err != nil {
		return nil, err
	}
	controls, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading controls: %w", err)
	}

	ctlByID := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		ctlByID[controls[i].ID] = &controls[i]
	}
	return ctlByID, nil
}

// loadAssetProperties extracts the properties of a specific asset from the latest snapshot.
func loadAssetProperties(ctx context.Context, loadSnapshots compose.SnapshotLoader, dir string, assetID asset.ID) (string, error) {
	snapshots, err := loadSnapshots(ctx, dir)
	if err != nil {
		return "", err
	}
	latest, latestErr := compose.LatestSnapshot(snapshots)
	if latestErr != nil {
		return "", nil // no snapshots is not an error for optional asset properties
	}
	for _, a := range latest.Assets {
		if a.ID == assetID {
			propsJSON, marshalErr := json.MarshalIndent(a.Properties, "", "  ")
			if marshalErr != nil {
				return "", fmt.Errorf("marshal asset properties: %w", marshalErr)
			}
			return string(propsJSON), nil
		}
	}
	return "", nil
}
