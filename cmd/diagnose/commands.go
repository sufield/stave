// Package diagnose implements the diagnose command and its subcommands:
// trace, explain-narrative.
package diagnose

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewDiagnoseCmd constructs the diagnose command.
func NewDiagnoseCmd(newObsRepo compose.ObsRepoFactory, newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	var opts diagnoseOptions

	cmd := &cobra.Command{
		Use:     "diagnose",
		Aliases: []string{"diag"},
		Short:   "Diagnose evaluation inputs and results",
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

Subcommands:
  finding    Deep-dive analysis of a single control/asset violation

Exit Codes:
  0   - No diagnostic issues found
  2   - Invalid input or error
  3   - Diagnostic issues detected
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Basic diagnosis
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

  # Deep dive into a single finding (subcommand)
  stave diagnose finding --control-id CTL.S3.PUBLIC.001 --asset-id my-bucket \
    --controls ./controls --observations ./obs`,
		Args:          cobra.NoArgs,
		Annotations:   map[string]string{cmdutil.AnnotationSanitizeAware: "true"},
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := cliflags.GetGlobalFlags(cmd)
			// Page the human report to a terminal; never page JSON. The pager
			// wraps the writer threaded into the diagnosis Config, so all report
			// output flows through it.
			pageable := !opts.NoPager && opts.Format != "json"
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			defer func() { _ = closePager() }()
			cfg, err := toConfig(&opts, flags, pw, cmd.ErrOrStderr(), cmd.InOrStdin())
			if err != nil {
				return err
			}
			obsRepo, err := newObsRepo()
			if err != nil {
				return fmt.Errorf("create observation loader: %w", err)
			}
			ctlRepo, err := newCtlRepo()
			if err != nil {
				return fmt.Errorf("create control loader: %w", err)
			}
			runner := NewRunner(obsRepo, ctlRepo, cfg.Clock)
			return runner.Run(cmd.Context(), cfg)
		},
	}

	opts.BindFlags(cmd)
	cmd.AddCommand(NewFindingCmd(newObsRepo, newCtlRepo))

	return cmd
}
