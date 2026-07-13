// Package verify implements the apply verify subcommand that compares
// before and after evaluation snapshots to detect resolved, remaining,
// and newly introduced violations.
package verify

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

// NewCmd builds the verify command.
func NewCmd(rt *ui.Runtime) *cobra.Command {
	opts := newOptions()

	cmd := &cobra.Command{
		Use:   "check",
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
  --eval-time                    Evaluation reference timestamp (RFC3339) for deterministic output

Outputs:
  stdout                   Verification report JSON showing resolved, remaining,
                           and introduced findings
  stderr                   Error messages (if any)

Exit Codes:
  0   - All findings resolved; no remaining or introduced violations
  3   - Remaining or introduced violations exist
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Compare before/after observations
  stave check --before ./obs-before --after ./obs-after --controls ./controls

  # Deterministic output for CI
  stave check --before ./obs-before --after ./obs-after --controls ./controls \
    --eval-time 2026-01-15T00:00:00Z

  # With a custom unsafe duration threshold
  stave check --before ./obs-before --after ./obs-after --controls ./controls \
    --max-unsafe 72h`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			opts.resolveConfigDefaults(cmd)
			opts.normalize()
			return opts.validate()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)

			out, hasViolations, err := stave.VerifyRemediation(cmd.Context(), stave.VerifyConfig{
				BeforeDir:   opts.BeforeDir,
				AfterDir:    opts.AfterDir,
				ControlsDir: opts.ControlsDir,
				MaxUnsafe:   opts.MaxUnsafeDuration,
				EvalTime:    opts.EvalTime,
				SanitizeIDs: gf.Sanitize,
				PathMode:    string(gf.PathMode),
				Progress:    rt.BeginProgress,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}

			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write verification report: %w", werr)
			}
			if hasViolations {
				return ui.ErrViolationsFound
			}
			return nil
		},
		Annotations:   map[string]string{cmdutil.AnnotationSanitizeAware: "true"},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
