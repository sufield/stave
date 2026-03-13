package diagnose

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// PromptConfig defines the parameters for generating an LLM prompt.
type PromptConfig struct {
	EvalFile        string
	AssetID         string
	ControlsDir     string
	ObservationsDir string
	Format          ui.OutputFormat
	Quiet           bool
	Stdout          io.Writer
	Stderr          io.Writer
}

// PromptResult represents the structured JSON output for a prompt.
type PromptResult struct {
	Prompt     string   `json:"prompt"`
	FindingIDs []string `json:"finding_ids"`
	AssetID    string   `json:"asset_id"`
}

// PromptRunner orchestrates collection of context and generation of prompts.
type PromptRunner struct {
	Provider *compose.Provider
}

// NewPromptRunner creates a runner with the provided dependency provider.
func NewPromptRunner(p *compose.Provider) *PromptRunner {
	return &PromptRunner{Provider: p}
}

// Run generates an LLM prompt based on evaluation findings.
func (r *PromptRunner) Run(ctx context.Context, cfg PromptConfig) error {
	if cfg.EvalFile == "" {
		return fmt.Errorf("--evaluation-file is required")
	}
	if cfg.AssetID == "" {
		return fmt.Errorf("--asset-id is required")
	}

	evalResult, err := evaljson.NewLoader().LoadFromFile(cfg.EvalFile)
	if err != nil {
		return fmt.Errorf("load evaluation file: %w", err)
	}

	matched := appdiagnose.FilterFindings(evalResult.Findings, asset.ID(cfg.AssetID))
	if len(matched) == 0 {
		return fmt.Errorf("no findings for asset %q in %s", cfg.AssetID, cfg.EvalFile)
	}

	ctlByID, err := r.loadControlsMap(ctx, cfg.ControlsDir)
	if err != nil {
		return err
	}

	var assetPropsJSON string
	if cfg.ObservationsDir != "" {
		assetPropsJSON, err = r.loadAssetProperties(ctx, cfg.ObservationsDir, cfg.AssetID)
		if err != nil {
			return err
		}
	}

	builder := &appdiagnose.PromptBuilder{
		AssetID:        cfg.AssetID,
		ControlsByID:   ctlByID,
		AssetPropsJSON: assetPropsJSON,
	}
	data := builder.Build(matched)
	rendered := appdiagnose.RenderPrompt(data)

	return r.write(cfg, rendered, data)
}

func (r *PromptRunner) loadControlsMap(ctx context.Context, dir string) (map[string]*policy.ControlDefinition, error) {
	repo, err := r.Provider.NewControlRepo()
	if err != nil {
		return nil, err
	}
	controls, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("loading controls: %w", err)
	}

	ctlByID := make(map[string]*policy.ControlDefinition, len(controls))
	for i := range controls {
		ctlByID[controls[i].ID.String()] = &controls[i]
	}
	return ctlByID, nil
}

func (r *PromptRunner) loadAssetProperties(ctx context.Context, dir, assetID string) (string, error) {
	snapshots, err := r.Provider.LoadSnapshots(ctx, dir)
	if err != nil {
		return "", err
	}
	if len(snapshots) == 0 {
		return "", nil
	}

	latest := asset.LatestSnapshot(snapshots)
	for _, a := range latest.Assets {
		if a.ID.String() == assetID {
			propsJSON, marshalErr := json.MarshalIndent(a.Properties, "", "  ")
			if marshalErr != nil {
				return "", fmt.Errorf("marshal asset properties: %w", marshalErr)
			}
			return string(propsJSON), nil
		}
	}
	return "", nil
}

func (r *PromptRunner) write(cfg PromptConfig, rendered string, data appdiagnose.PromptData) error {
	out := cfg.Stdout
	if cfg.Quiet && !cfg.Format.IsJSON() {
		out = io.Discard
	}

	if cfg.Format.IsJSON() {
		findingIDs := make([]string, len(data.Findings))
		for i, f := range data.Findings {
			findingIDs[i] = string(f.ControlID)
		}
		res := PromptResult{
			Prompt:     rendered,
			FindingIDs: findingIDs,
			AssetID:    data.AssetID,
		}
		return jsonutil.WriteIndented(out, res)
	}

	if _, err := fmt.Fprint(out, rendered); err != nil {
		return err
	}
	writeClipboardHint(cfg.Stderr, cfg.Quiet)
	return nil
}

func writeClipboardHint(w io.Writer, quiet bool) {
	if quiet {
		return
	}
	var tool string
	switch runtime.GOOS {
	case "darwin":
		tool = "pbcopy"
	case "linux":
		tool = "xclip -selection clipboard"
	default:
		return
	}
	fmt.Fprintf(w, "Hint: pipe to clipboard with:\n  stave prompt from-finding ... | %s\n", tool)
}

// --- CLI bridge ---

// NewPromptCmd constructs the prompt command group.
func NewPromptCmd() *cobra.Command {
	promptCmd := &cobra.Command{
		Use:   "prompt",
		Short: "Generate LLM prompts from evaluation results",
		Long:  "Grouped prompt generation commands: from-finding." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	promptCmd.AddCommand(newPromptFromFindingCmd())

	return promptCmd
}

func newPromptFromFindingCmd() *cobra.Command {
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

			runner := NewPromptRunner(compose.ActiveProvider())
			return runner.Run(cmd.Context(), PromptConfig{
				EvalFile:        fsutil.CleanUserPath(evalFile),
				AssetID:         strings.TrimSpace(assetID),
				ControlsDir:     fsutil.CleanUserPath(controlsDir),
				ObservationsDir: fsutil.CleanUserPath(obsDir),
				Format:          fmtValue,
				Quiet:           quietMode || cmdutil.GetGlobalFlags(cmd).Quiet,
				Stdout:          cmd.OutOrStdout(),
				Stderr:          cmd.ErrOrStderr(),
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
