package verify

import (
	"context"
	"io"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appverify "github.com/sufield/stave/internal/app/verify"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// NewCmd builds the verify command.
func NewCmd(p *compose.Provider, _ *ui.Runtime) *cobra.Command {
	opts := newOptions()

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Compare before/after evaluations to check remediation",
		Long: `Verify runs the same controls against two sets of observations
(before and after remediation) and reports which findings were resolved,
which remain, and which are newly introduced.` + metadata.OfflineHelpSuffix,
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

			celEval, err := p.NewCELEvaluator()
			if err != nil {
				return err
			}

			gf := cmdutil.GetGlobalFlags(cmd)

			return appverify.RunVerify(
				appverify.VerifyDeps{
					LoadControls: func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
						return compose.LoadControls(ctx, p, dir)
					},
					NewObservationRepo: func() (appcontracts.ObservationRepository, error) {
						return p.NewObservationRepo()
					},
					WriteVerification: func(w io.Writer, v safetyenvelope.Verification) error {
						return outjson.WriteVerification(w, v)
					},
				},
				appverify.VerifyRequest{
					Ctx:          exec.Context,
					BeforeDir:    exec.BeforeDir,
					AfterDir:     exec.AfterDir,
					ControlsDir:  exec.ControlsDir,
					MaxUnsafe:    exec.MaxUnsafe,
					Clock:        exec.Clock,
					AllowUnknown: exec.AllowUnknown,
					Quiet:        gf.Quiet,
					Sanitizer:    gf.GetSanitizer(),
					Stdout:       cmd.OutOrStdout(),
					CELEvaluator: celEval,
				},
			)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
