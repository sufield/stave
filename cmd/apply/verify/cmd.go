package verify

import (
	"context"
	"io"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appverify "github.com/sufield/stave/internal/app/verify"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/safetyenvelope"
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

			return appverify.RunVerify(
				appverify.Deps{
					LoadControls: func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
						return compose.LoadControlsFrom(ctx, newCtlRepo, dir)
					},
					NewObservationRepo: func() (appcontracts.ObservationRepository, error) {
						return newObsRepo()
					},
					WriteVerification: func(w io.Writer, v *safetyenvelope.Verification) error {
						return outjson.WriteVerification(w, v)
					},
					BeginProgress: rt.BeginProgress,
				},
				appverify.Request{
					Ctx:               exec.Context,
					BeforeDir:         exec.BeforeDir,
					AfterDir:          exec.AfterDir,
					ControlsDir:       exec.ControlsDir,
					MaxUnsafeDuration: exec.MaxUnsafeDuration,
					Clock:             exec.Clock,
					AllowUnknown:      exec.AllowUnknown,
					Quiet:             gf.Quiet,
					Sanitizer:         gf.GetSanitizer(),
					Stdout:            cmd.OutOrStdout(),
					CELEvaluator:      celEval,
				},
			)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
