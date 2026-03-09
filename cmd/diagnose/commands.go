package diagnose

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/metadata"
)

// NewDiagnoseCmd constructs the diagnose command with closure-scoped flags.
func NewDiagnoseCmd() *cobra.Command {
	var opts diagnoseOptions

	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Diagnose evaluation inputs and results",
		Long: `Diagnose analyzes evaluation inputs and results to identify likely causes
when results don't match expectations.

Purpose: Understand why evaluation produced (or didn't produce) certain findings.

Inputs:
  --controls      Directory containing YAML control definitions
  --observations    Directory containing JSON observation snapshots
  --previous-output Optional path to existing apply output JSON

Outputs:
  stdout            Diagnostic report (text or JSON with --format json)
  stderr            Error messages (if any)

What it explains:
  - Expected violations but got none (threshold too high, time span too short)
  - Unexpected violations (clock skew, streak reset)
  - Empty findings (no predicate matches, under threshold)
  - Configuration mismatches

Finding Detail mode (--control-id + --asset-id):
  When both flags are set, diagnose switches to a single-finding deep dive
  showing control metadata, predicate evaluation trace, evidence,
  remediation guidance, and next steps.

Exit Codes:
  0   - No diagnostic issues found
  2   - Invalid input or error
  3   - Diagnostic issues detected
  130 - Interrupted (SIGINT)

Examples:
  # Basic diagnosis
  stave diagnose --controls ./controls --observations ./obs

  # Automation/CI mode (exit code only)
  stave diagnose --controls ./controls --observations ./obs --quiet

  # Troubleshooting an existing apply output
  stave diagnose --previous-output previous-run.json --controls ./controls --observations ./obs

  # JSON output for scripting
  stave diagnose --controls ./controls --observations ./obs --format json

  # Show only threshold/span diagnostics
  stave diagnose --controls ./controls --observations ./obs --case expected_violations_none

  # Diagnose from stdin (pipe evaluation output)
  stave apply --controls ./controls --observations ./obs | stave diagnose --previous-output - --controls ./controls --observations ./obs

  # Deep dive into a single finding (finding detail mode)
  stave diagnose --controls ./controls --observations ./obs \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id res:aws:s3:bucket:my-bucket

  # Same with existing evaluation output
  stave diagnose --previous-output output/evaluation.json \
    --controls ./controls --observations ./obs \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id res:aws:s3:bucket:my-bucket \
    --format json
` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiagnose(cmd, &opts)
		},
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	cmd.Flags().StringVarP(&opts.PreviousOutput, "previous-output", "p", "", "Path to existing apply output JSON (optional; if omitted, runs apply internally)")
	cmd.Flags().StringVar(&opts.MaxUnsafe, "max-unsafe", projconfig.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	cmd.Flags().StringVar(&opts.NowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&opts.Quiet, "quiet", projconfig.ResolveQuietDefault(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))
	cmd.Flags().StringSliceVar(&opts.Cases, "case", nil, "Filter to one or more diagnostic case values")
	cmd.Flags().StringVar(&opts.SignalContains, "signal-contains", "", "Filter diagnostics by signal substring (case-insensitive)")
	cmd.Flags().StringVar(&opts.Template, "template", "", "Template string for custom output formatting (supports {{.Field}}, {{range}}, {{json}})")
	cmd.Flags().StringVar(&opts.ControlID, "control-id", "", "Control ID for single-finding detail mode (requires --asset-id)")
	cmd.Flags().StringVar(&opts.AssetID, "asset-id", "", "Asset ID for single-finding detail mode (requires --control-id)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("case", cmdutil.CompleteFixed(
		string(diagnosis.ExpectedNone),
		string(diagnosis.ViolationEvidence),
		string(diagnosis.EmptyFindings),
	))

	return cmd
}
