//go:build stavedev

package diagnose

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	promptout "github.com/sufield/stave/internal/adapters/output/prompt"
	diagprompt "github.com/sufield/stave/internal/app/diagnose/prompt"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// --- CLI bridge ---

// NewPromptCmd constructs the prompt command group.
func NewPromptCmd(p *compose.Provider) *cobra.Command {
	promptCmd := &cobra.Command{
		Use:   "prompt",
		Short: "Generate LLM prompts from evaluation results",
		Long:  "Grouped prompt generation commands: from-finding." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	promptCmd.AddCommand(newPromptFromFindingCmd(p))

	return promptCmd
}

func newPromptFromFindingCmd(p *compose.Provider) *cobra.Command {
	var (
		evalFile    string
		assetID     string
		controlsDir string
		obsDir      string
		format      string
		quietMode   bool
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
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}

			ctx := cmd.Context()

			ctlByID, err := loadControlsMap(ctx, p, fsutil.CleanUserPath(controlsDir))
			if err != nil {
				return err
			}

			var assetPropsJSON string
			cleanObsDir := fsutil.CleanUserPath(obsDir)
			if cleanObsDir != "" {
				assetPropsJSON, err = loadAssetProperties(ctx, p, cleanObsDir, asset.ID(strings.TrimSpace(assetID)))
				if err != nil {
					return err
				}
			}

			dctx := diagprompt.DiagnosticContext{
				ControlsByID:   ctlByID,
				AssetPropsJSON: assetPropsJSON,
				LoadEval: func(path string) (*evaluation.Result, error) {
					return evaljson.NewLoader().LoadFromFile(path)
				},
				BuildPrompt: buildPromptAdapter,
			}

			runner := diagprompt.NewRunner(dctx)
			return runner.Run(ctx, diagprompt.Config{
				EvalFile: fsutil.CleanUserPath(evalFile),
				AssetID:  strings.TrimSpace(assetID),
				Format:   fmtValue,
				Quiet:    quietMode || cmdutil.GetGlobalFlags(cmd).Quiet,
				Stdout:   cmd.OutOrStdout(),
				Stderr:   cmd.ErrOrStderr(),
			})
		},
	}

	cmd.Flags().StringVar(&evalFile, "evaluation-file", "", "Path to evaluation JSON output (required)")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "Asset ID to filter findings (required)")
	cmd.Flags().StringVarP(&controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&obsDir, "observations", "o", "", "Path to observation snapshots directory (optional)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&quietMode, "quiet", projconfig.Global().Quiet(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	_ = cmd.MarkFlagRequired("evaluation-file")
	_ = cmd.MarkFlagRequired("asset-id")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

// buildPromptAdapter bridges the app-layer BuildFunc contract to the
// adapters/output/prompt implementation.
func buildPromptAdapter(
	assetID string,
	controlsByID map[kernel.ControlID]*policy.ControlDefinition,
	assetPropsJSON string,
	matched []evaluation.Finding,
) diagprompt.PromptOutput {
	builder := &promptout.PromptBuilder{
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
	return diagprompt.PromptOutput{
		Rendered:   rendered,
		FindingIDs: findingIDs,
		AssetID:    data.AssetID,
	}
}

// loadControlsMap loads control definitions and indexes them by ID.
func loadControlsMap(ctx context.Context, p *compose.Provider, dir string) (map[kernel.ControlID]*policy.ControlDefinition, error) {
	repo, err := p.NewControlRepo()
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
func loadAssetProperties(ctx context.Context, p *compose.Provider, dir string, assetID asset.ID) (string, error) {
	snapshots, err := p.LoadSnapshots(ctx, dir)
	if err != nil {
		return "", err
	}
	if len(snapshots) == 0 {
		return "", nil
	}

	latest := snapshots[0]
	for _, s := range snapshots[1:] {
		if s.CapturedAt.After(latest.CapturedAt) {
			latest = s
		}
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
