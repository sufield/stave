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
	"github.com/sufield/stave/internal/platform/fsutil"
)

type promptFlagsType struct {
	evalFile    string
	assetID     string
	controlsDir string
	obsDir      string
	format      string
	quietMode   bool
}

// NewPromptCmd constructs the prompt command group with closure-scoped flags.
func NewPromptCmd() *cobra.Command {
	var flags promptFlagsType

	promptCmd := &cobra.Command{
		Use:   "prompt",
		Short: "Generate LLM prompts from evaluation results",
		Long:  "Grouped prompt generation commands: from-finding." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	fromFindingCmd := &cobra.Command{
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
			return runPromptFromFinding(cmd, &flags)
		},
	}

	fromFindingCmd.Flags().StringVar(&flags.evalFile, "evaluation-file", "", "Path to evaluation JSON output (required)")
	fromFindingCmd.Flags().StringVar(&flags.assetID, "asset-id", "", "Asset ID to filter findings (required)")
	fromFindingCmd.Flags().StringVarP(&flags.controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	fromFindingCmd.Flags().StringVarP(&flags.obsDir, "observations", "o", "", "Path to observation snapshots directory (optional)")
	fromFindingCmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	fromFindingCmd.Flags().BoolVar(&flags.quietMode, "quiet", projconfig.ResolveQuietDefault(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	_ = fromFindingCmd.MarkFlagRequired("evaluation-file")
	_ = fromFindingCmd.MarkFlagRequired("asset-id")
	_ = fromFindingCmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	promptCmd.AddCommand(fromFindingCmd)

	return promptCmd
}

type promptRunOptions struct {
	EvalFile        string
	AssetID         string
	ControlsDir     string
	ObservationsDir string
	Format          ui.OutputFormat
	Quiet           bool
}

func runPromptFromFinding(cmd *cobra.Command, flags *promptFlagsType) error {
	opts, err := gatherPromptFromFindingOptions(cmd, flags)
	if err != nil {
		return err
	}

	// 1. Load evaluation output and narrow to asset findings.
	evalResult, err := evaljson.NewLoader().LoadFromFile(opts.EvalFile)
	if err != nil {
		return fmt.Errorf("load evaluation file: %w", err)
	}

	matched := appdiagnose.FilterFindings(evalResult.Findings, opts.AssetID)
	if len(matched) == 0 {
		return fmt.Errorf("no findings for asset %q in %s", opts.AssetID, opts.EvalFile)
	}

	// 2. Load enrichment sources (controls + optional observations).
	ctx := compose.CommandContext(cmd)

	ctlByID, err := loadControlsMap(ctx, opts.ControlsDir)
	if err != nil {
		return err
	}

	assetPropsJSON := ""
	if opts.ObservationsDir != "" {
		assetPropsJSON, err = loadAssetProperties(ctx, opts.ObservationsDir, opts.AssetID)
		if err != nil {
			return err
		}
	}

	// 3. Build, render, and emit output.
	builder := &appdiagnose.PromptBuilder{
		AssetID:        opts.AssetID,
		ControlsByID:   ctlByID,
		AssetPropsJSON: assetPropsJSON,
	}
	data := builder.Build(matched)
	rendered := appdiagnose.RenderPrompt(data)
	return writePromptOutput(opts, cmd.OutOrStdout(), cmd.ErrOrStderr(), rendered, data)
}

func gatherPromptFromFindingOptions(cmd *cobra.Command, flags *promptFlagsType) (promptRunOptions, error) {
	format, err := compose.ResolveFormatValue(cmd, flags.format)
	if err != nil {
		return promptRunOptions{}, err
	}

	opts := promptRunOptions{
		EvalFile:        fsutil.CleanUserPath(flags.evalFile),
		AssetID:         strings.TrimSpace(flags.assetID),
		ControlsDir:     fsutil.CleanUserPath(flags.controlsDir),
		ObservationsDir: fsutil.CleanUserPath(flags.obsDir),
		Format:          format,
		Quiet:           flags.quietMode || cmdutil.QuietEnabled(cmd),
	}

	if opts.EvalFile == "" {
		return promptRunOptions{}, fmt.Errorf("--evaluation-file is required")
	}
	if opts.AssetID == "" {
		return promptRunOptions{}, fmt.Errorf("--asset-id is required")
	}
	return opts, nil
}

func loadControlsMap(ctx context.Context, dir string) (map[string]*policy.ControlDefinition, error) {
	controls, err := compose.LoadControls(ctx, dir)
	if err != nil {
		return nil, err
	}

	ctlByID := make(map[string]*policy.ControlDefinition, len(controls))
	for i := range controls {
		ctlByID[controls[i].ID.String()] = &controls[i]
	}
	return ctlByID, nil
}

func writePromptOutput(opts promptRunOptions, stdout, stderr io.Writer, rendered string, data appdiagnose.PromptData) error {
	out := stdout
	if opts.Quiet && !opts.Format.IsJSON() {
		out = io.Discard
	}

	if opts.Format.IsJSON() {
		jsonOut := promptJSONOutput{
			Prompt:     rendered,
			FindingIDs: collectFindingIDs(data.Findings),
			AssetID:    data.AssetID,
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(jsonOut); err != nil {
			return err
		}
	} else if _, err := fmt.Fprint(out, rendered); err != nil {
		return err
	}

	clipboardHint(stderr, opts.Quiet)
	return nil
}

// clipboardHint prints a hint for piping output to the system clipboard.
// Only prints when not in quiet mode and a known clipboard tool exists.
func clipboardHint(w io.Writer, quiet bool) {
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

func collectFindingIDs(findings []appdiagnose.FindingData) []string {
	findingIDs := make([]string, 0, len(findings))
	for _, f := range findings {
		findingIDs = append(findingIDs, f.ControlID)
	}
	return findingIDs
}

// promptJSONOutput is the structured JSON output.
type promptJSONOutput struct {
	Prompt     string   `json:"prompt"`
	FindingIDs []string `json:"finding_ids"`
	AssetID    string   `json:"asset_id"`
}

// loadAssetProperties loads the latest observation snapshot and extracts
// properties for the given asset ID as indented JSON.
func loadAssetProperties(ctx context.Context, obsDir, assetID string) (string, error) {
	snapshots, err := compose.LoadSnapshots(ctx, obsDir)
	if err != nil {
		return "", err
	}
	if len(snapshots) == 0 {
		return "", nil
	}

	latest := asset.LatestSnapshot(snapshots)

	for _, r := range latest.Assets {
		if r.ID.String() == assetID {
			propsJSON, err := json.MarshalIndent(r.Properties, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshal asset properties: %w", err)
			}
			return string(propsJSON), nil
		}
	}

	return "", nil
}
