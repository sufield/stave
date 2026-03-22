package diagnose

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
)

// NewDiagnoseCmd constructs the diagnose command.
func NewDiagnoseCmd(p *compose.Provider) *cobra.Command {
	var opts diagnoseOptions

	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Diagnose evaluation inputs and results",
		Long: `Diagnose evaluation inputs and results to identify likely causes of unexpected findings.

Diagnose analyzes controls, observations, and optional prior output to explain
why an evaluation produced (or did not produce) certain findings. It is useful
for troubleshooting threshold mismatches, clock skew, and predicate logic.

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
			opts.resolveConfigDefaults(cmd)
			cfg, err := opts.ToConfig(cmd)
			if err != nil {
				return err
			}
			runner := NewRunner(p, cfg.Clock)
			return runner.Run(cmd.Context(), cfg)
		},
	}

	opts.BindFlags(cmd)

	return cmd
}
