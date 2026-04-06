// Package verify implements the apply verify subcommand that compares
// before and after evaluation snapshots to detect resolved, remaining,
// and newly introduced violations.
package verify

import (
	"context"
	"io"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appattest "github.com/sufield/stave/internal/app/attestation"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd builds the verify command.
func NewCmd(newObsRepo compose.ObsRepoFactory, newCtlRepo compose.CtlRepoFactory, newCELEvaluator compose.CELEvaluatorFactory, rt *ui.Runtime) *cobra.Command {
	opts := newOptions()

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Compare before/after evaluations to check remediation",
		Long: `Compare before/after evaluations to check whether remediation resolved findings.

Verify runs the same controls against two sets of observations (before and after
remediation) and reports which findings were resolved, which remain, and which
are newly introduced. Use it after applying fixes to confirm that violations
have been addressed without introducing regressions.

Inputs:
  --before, -b             Path to before-remediation observations (required)
  --after, -a              Path to after-remediation observations (required)
  --controls, -i           Path to control definitions directory (default: controls)
  --max-unsafe             Maximum allowed unsafe duration
  --now                    Override current time (RFC3339) for deterministic output
  --allow-unknown-input    Allow observations with unknown source types

Outputs:
  stdout                   Verification report JSON showing resolved, remaining,
                           and introduced findings
  stderr                   Error messages (if any)

Exit Codes:
  0   - All findings resolved; no remaining or introduced violations
  3   - Remaining or introduced violations exist
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Compare before/after observations
  stave verify --before ./obs-before --after ./obs-after --controls ./controls

  # Deterministic output for CI
  stave verify --before ./obs-before --after ./obs-after --controls ./controls \
    --now 2026-01-15T00:00:00Z

  # With a custom unsafe duration threshold
  stave verify --before ./obs-before --after ./obs-after --controls ./controls \
    --max-unsafe 72h`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			opts.resolveConfigDefaults(cmd)
			opts.normalize()
			return opts.validate()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			exec, err := opts.Complete(compose.CommandContext(cmd))
			if err != nil {
				return err
			}

			celEval, err := newCELEvaluator()
			if err != nil {
				return err
			}

			gf := cliflags.GetGlobalFlags(cmd)

			return appattest.PerformAttestation(
				appattest.WorkflowDeps{
					LoadPolicies: func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
						return compose.LoadControlsFrom(ctx, newCtlRepo, dir)
					},
					NewInventoryRepo: func() (appcontracts.ObservationRepository, error) {
						return newObsRepo()
					},
					PublishAttestation: func(w io.Writer, v *report.Attestation) error {
						return outjson.WriteVerification(w, v)
					},
					BeginStage: rt.BeginProgress,
				},
				appattest.Request{
					Ctx:            exec.Context,
					BaselineSource: exec.BeforeDir,
					TargetSource:   exec.AfterDir,
					PolicySource:   exec.ControlsDir,
					SLAThreshold:   exec.MaxUnsafeDuration,
					Clock:          exec.Clock,
					AllowUnknown:   exec.AllowUnknown,
					Quiet:          gf.Quiet,
					Sanitizer:      gf.GetSanitizer(),
					Stdout:         cmd.OutOrStdout(),
					PredicateEval:  celEval,
				},
			)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
