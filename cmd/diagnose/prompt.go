package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
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

	matched := filterFindings(evalResult.Findings, opts.AssetID)
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
	builder := &promptBuilder{
		assetID:        opts.AssetID,
		controlsByID:   ctlByID,
		assetPropsJSON: assetPropsJSON,
	}
	data := builder.build(matched)
	rendered := renderPrompt(data)
	return writePromptOutput(opts, cmd.OutOrStdout(), rendered, data)
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

func filterFindings(all []evaluation.Finding, assetID string) []evaluation.Finding {
	matched := make([]evaluation.Finding, 0, len(all))
	for _, v := range all {
		if string(v.AssetID) == assetID {
			matched = append(matched, v)
		}
	}
	return matched
}

func writePromptOutput(opts promptRunOptions, stdout io.Writer, rendered string, data promptData) error {
	out := stdout
	if opts.Quiet {
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

	clipboardHint(opts.Quiet)
	return nil
}

// clipboardHint prints a hint for piping output to the system clipboard.
// Only prints when not in quiet mode and a known clipboard tool exists.
func clipboardHint(quiet bool) {
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
	fmt.Fprintf(os.Stderr, "Hint: pipe to clipboard with:\n  stave prompt from-finding ... | %s\n", tool)
}

func collectFindingIDs(findings []promptFindingData) []string {
	findingIDs := make([]string, 0, len(findings))
	for _, f := range findings {
		findingIDs = append(findingIDs, f.ControlID)
	}
	return findingIDs
}

// promptFindingData holds data for a single finding in the rendered prompt.
type promptFindingData struct {
	ControlID    string
	ControlName  string
	Description  string
	AssetID      string
	AssetType    string
	Evidence     string
	MatchedProps string
	RootCauses   string
	ControlYAML  string
	Guidance     string
}

// promptData holds all data for the prompt rendering.
type promptData struct {
	FindingCount    int
	AssetID         string
	Findings        []promptFindingData
	AssetProperties string
}

// promptJSONOutput is the structured JSON output.
type promptJSONOutput struct {
	Prompt     string   `json:"prompt"`
	FindingIDs []string `json:"finding_ids"`
	AssetID    string   `json:"asset_id"`
}

// promptBuilder coordinates assembly of LLM-ready prompt data.
type promptBuilder struct {
	assetID        string
	controlsByID   map[string]*policy.ControlDefinition
	assetPropsJSON string
}

func (b *promptBuilder) build(matched []evaluation.Finding) promptData {
	findings := make([]promptFindingData, 0, len(matched))

	for _, v := range matched {
		fd := promptFindingData{
			ControlID:    string(v.ControlID),
			ControlName:  v.ControlName,
			Description:  v.ControlDescription,
			AssetID:      string(v.AssetID),
			AssetType:    string(v.AssetType),
			Evidence:     buildEvidenceSummary(v.Evidence),
			MatchedProps: b.summarizeMisconfigurations(v.Evidence.Misconfigurations),
			RootCauses:   buildRootCausesSummary(v.Evidence.RootCauses),
		}

		if ctl, ok := b.controlsByID[string(v.ControlID)]; ok {
			fd.ControlYAML = b.marshalControl(ctl)
			if ctl.Remediation != nil {
				remediation := policy.RemediationSpec{
					Description: ctl.Remediation.Description,
					Action:      ctl.Remediation.Action,
					Example:     ctl.Remediation.Example,
				}
				fd.Guidance = buildGuidanceSummary(&remediation)
			}
		}
		findings = append(findings, fd)
	}

	return promptData{
		FindingCount:    len(findings),
		AssetID:         b.assetID,
		Findings:        findings,
		AssetProperties: b.assetPropsJSON,
	}
}

func (b *promptBuilder) summarizeMisconfigurations(misconfigs []policy.Misconfiguration) string {
	if len(misconfigs) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, mc := range misconfigs {
		sb.WriteString("- ")
		sb.WriteString(mc.String())
		sb.WriteString("\n")
	}
	return strings.TrimSpace(sb.String())
}

func (b *promptBuilder) marshalControl(ctl *policy.ControlDefinition) string {
	yamlBytes, err := yaml.Marshal(ctl)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(yamlBytes))
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

// buildEvidenceSummary creates a human-readable summary of violation evidence.
func buildEvidenceSummary(ev evaluation.Evidence) string {
	var lines []string

	if !ev.FirstUnsafeAt.IsZero() {
		lines = append(lines, fmt.Sprintf("- First unsafe: %s", ev.FirstUnsafeAt.Format(time.RFC3339)))
	}
	if !ev.LastSeenUnsafeAt.IsZero() {
		lines = append(lines, fmt.Sprintf("- Last seen unsafe: %s", ev.LastSeenUnsafeAt.Format(time.RFC3339)))
	}
	if ev.UnsafeDurationHours > 0 {
		lines = append(lines, fmt.Sprintf("- Unsafe duration: %.1f hours", ev.UnsafeDurationHours))
	}
	if ev.ThresholdHours > 0 {
		lines = append(lines, fmt.Sprintf("- Threshold: %.1f hours", ev.ThresholdHours))
	}
	if ev.EpisodeCount > 0 {
		lines = append(lines, fmt.Sprintf("- Episodes: %d", ev.EpisodeCount))
	}
	if ev.WindowDays > 0 {
		lines = append(lines, fmt.Sprintf("- Window: %d days", ev.WindowDays))
	}
	if ev.RecurrenceLimit > 0 {
		lines = append(lines, fmt.Sprintf("- Recurrence limit: %d", ev.RecurrenceLimit))
	}
	if ev.WhyNow != "" {
		lines = append(lines, fmt.Sprintf("- Why now: %s", ev.WhyNow))
	}

	if len(lines) == 0 {
		return "No evidence details available."
	}
	return strings.Join(lines, "\n")
}

// buildRootCausesSummary creates a comma-separated root causes string.
func buildRootCausesSummary(causes []evaluation.RootCause) string {
	if len(causes) == 0 {
		return ""
	}
	parts := make([]string, len(causes))
	for i, c := range causes {
		parts[i] = string(c)
	}
	return strings.Join(parts, ", ")
}

// buildGuidanceSummary creates readable action guidance from control metadata.
func buildGuidanceSummary(m *policy.RemediationSpec) string {
	var parts []string
	if m.Description != "" {
		parts = append(parts, strings.TrimSpace(m.Description))
	}
	if m.Action != "" {
		parts = append(parts, "**Action:** "+strings.TrimSpace(m.Action))
	}
	if m.Example != "" {
		parts = append(parts, "**Example:**\n```\n"+strings.TrimSpace(m.Example)+"\n```")
	}
	return strings.Join(parts, "\n\n")
}

// renderPrompt builds the Markdown prompt from assembled data.
func renderPrompt(data promptData) string {
	var b bytes.Buffer

	fmt.Fprintf(&b, "# Stave Finding Analysis\n\n")
	fmt.Fprintf(&b, "I am using **Stave**, an offline configuration safety evaluator, to detect infrastructure misconfigurations. ")
	fmt.Fprintf(&b, "Stave found **%d finding(s)** for asset `%s` that I need help analyzing and correcting.\n", data.FindingCount, data.AssetID)

	for _, f := range data.Findings {
		fmt.Fprintf(&b, "\n---\n\n")
		fmt.Fprintf(&b, "## Finding: %s\n\n", f.ControlID)
		fmt.Fprintf(&b, "| Field | Value |\n")
		fmt.Fprintf(&b, "|-------|-------|\n")
		fmt.Fprintf(&b, "| Control | %s |\n", f.ControlID)
		fmt.Fprintf(&b, "| Name | %s |\n", f.ControlName)
		fmt.Fprintf(&b, "| Description | %s |\n", strings.TrimSpace(f.Description))
		fmt.Fprintf(&b, "| Asset | %s |\n", f.AssetID)
		fmt.Fprintf(&b, "| Asset Type | %s |\n", f.AssetType)

		fmt.Fprintf(&b, "\n### Evidence\n\n%s\n", f.Evidence)

		if f.MatchedProps != "" {
			fmt.Fprintf(&b, "\n### Misconfigurations\n\n%s\n", f.MatchedProps)
		}

		if f.RootCauses != "" {
			fmt.Fprintf(&b, "\n### Root Causes\n\n%s\n", f.RootCauses)
		}

		if f.ControlYAML != "" {
			fmt.Fprintf(&b, "\n### Control Definition (YAML)\n\n```yaml\n%s\n```\n", f.ControlYAML)
		}

		if f.Guidance != "" {
			fmt.Fprintf(&b, "\n### Control Guidance\n\n%s\n", f.Guidance)
		}
	}

	if data.AssetProperties != "" {
		fmt.Fprintf(&b, "\n## Asset Properties (Latest Snapshot)\n\n```json\n%s\n```\n", data.AssetProperties)
	}

	fmt.Fprintf(&b, "\n## What I Need\n\n")
	fmt.Fprintf(&b, "Based on the findings above, please provide:\n\n")
	fmt.Fprintf(&b, "1. **Root cause analysis** — Why is this asset in an unsafe state?\n")
	fmt.Fprintf(&b, "2. **Corrective changes** — Specific, actionable changes to address each finding.\n")
	fmt.Fprintf(&b, "3. **Verification** — How to confirm the fix is applied correctly.\n")
	fmt.Fprintf(&b, "4. **Prevention** — What controls or automation would prevent recurrence?\n")

	return b.String()
}
