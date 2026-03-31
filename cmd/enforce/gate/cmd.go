package gate

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/eval"
	"github.com/sufield/stave/internal/metadata"
	formatter "github.com/sufield/stave/internal/ui"
)

// Deps groups the infrastructure implementations for the gate command.
type Deps struct {
	UseCaseDeps eval.GateDeps
}

// NewCmd constructs the CI gate command.
func NewCmd(deps Deps) *cobra.Command {
	opts := DefaultOptions()

	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Enforce CI failure policy modes from config or flags",
		Long: `Gate applies a CI failure policy and returns exit code 3 when the policy fails.

Supported policies:
  - fail_on_any_violation
  - fail_on_new_violation
  - fail_on_overdue_upcoming

Inputs:
  --policy          CI failure policy mode (default: from project config)
  --in              Path to evaluation JSON (required for fail_on_any/new)
  --baseline        Path to baseline JSON (required for fail_on_new_violation)
  --controls, -i    Path to control definitions directory (used by fail_on_overdue_upcoming)
  --observations, -o Path to observation snapshots directory (used by fail_on_overdue_upcoming)
  --max-unsafe      Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)
  --now             Reference time (RFC3339). If omitted, uses wall clock
  --format, -f      Output format: text or json (default: text)

Outputs:
  stdout            Gate result summary (text or JSON)
  stderr            Error messages (if any)

Exit Codes:
  0   - Policy passed; no violations detected
  2   - Invalid input or configuration error
  3   - Policy failed; violations detected
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Fail on any findings in evaluation output
  stave ci gate --policy fail_on_any_violation --in output/evaluation.json

  # Fail only on newly introduced findings
  stave ci gate --policy fail_on_new_violation --in output/evaluation.json --baseline output/baseline.json

  # Fail when any upcoming action is already overdue
  stave ci gate --policy fail_on_overdue_upcoming --controls ./controls --observations ./observations`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := toConfig(&opts, cliflags.GetGlobalFlags(cmd), cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			req := eval.GateRequest{
				Policy:            string(cfg.Policy),
				EvaluationPath:    cfg.InPath,
				BaselinePath:      cfg.BaselinePath,
				ControlsDir:       cfg.ControlsDir,
				ObservationsDir:   cfg.ObservationsDir,
				MaxUnsafeDuration: cfg.MaxUnsafeDuration,
			}

			resp, err := eval.Gate(cmd.Context(), req, deps.UseCaseDeps)
			if err != nil {
				return err
			}

			if cfg.Format.IsJSON() {
				if renderErr := formatter.RenderJSON(cfg.Stdout, resp); renderErr != nil {
					return renderErr
				}
			} else if !cfg.Quiet {
				status := "PASS"
				if !resp.Passed {
					status = "FAIL"
				}
				if renderErr := formatter.RenderText(cfg.Stdout, "Gate %s (%s): %s\n", status, resp.Policy, resp.Reason); renderErr != nil {
					return renderErr
				}
			}

			if !resp.Passed {
				return ui.ErrViolationsFound
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	registerCompletions(cmd)

	return cmd
}

func registerCompletions(cmd *cobra.Command) {
	_ = cmd.RegisterFlagCompletionFunc("policy", cliflags.CompleteFixed(appconfig.AllGatePolicies()...))
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))
}
