package fix

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

// NewFixCmd constructs the fix command.
func NewFixCmd() *cobra.Command {
	opts := &fixOptions{}

	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Show machine-readable fix plan for a finding",
		Long: `Fix reads an evaluation artifact and prints deterministic remediation guidance
for a single finding. It never modifies user files.

Inputs:
  --input       Path to evaluation JSON file (required)
  --finding     Finding selector: <control_id>@<asset_id> (required)

Outputs:
  stdout        Remediation guidance JSON for the selected finding

Exit Codes:
  0   - Guidance emitted successfully
  2   - Invalid input (missing file, bad selector)
  4   - Internal error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Show fix plan for a specific finding
  stave ci fix --input output/evaluation.json --finding CTL.S3.PUBLIC.001@res:aws:s3:bucket:my-bucket

  # Pipe to jq for structured inspection
  stave ci fix --input output/evaluation.json --finding CTL.S3.PUBLIC.001@res:aws:s3:bucket:my-bucket | jq .`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.FixFinding(cmd.Context(), opts.InputPath, opts.FindingRef)
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped ("run fix"); preserve exit 4.
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write output: %w", werr)
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

// NewFixLoopCmd constructs the fix-loop command.
func NewFixLoopCmd() *cobra.Command {
	opts := &loopOptions{
		ControlsDir: "controls",
	}

	cmd := &cobra.Command{
		Use:   "fix-loop",
		Short: "Run apply-before/apply-after/verify in one command",
		Long: `Fix-loop executes the remediation verification lifecycle in one run:
apply before state, apply after state, compare findings, and emit a
remediation report suitable for CI/CD.

Input:
  --before      Directory containing before-remediation observations
  --after       Directory containing after-remediation observations
  --controls  Directory containing control definitions

Output:
  stdout  remediation report JSON
  --out   writes evaluation.before.json, evaluation.after.json,
          verification.json, remediation-report.json

Exit Codes:
  0   - No remaining or introduced violations
  3   - Remaining or introduced violations exist` + metadata.OfflineHelpSuffix,
		Example: `  # Run a full fix-loop comparing before and after observations
  stave ci fix-loop --before ./obs-before --after ./obs-after --controls ./controls --out ./output --eval-time 2026-01-11T00:00:00Z

  # Run in CI with a strict 72-hour threshold
  stave ci fix-loop --before ./obs-before --after ./obs-after --controls ./controls --out ./output --max-unsafe 72h --eval-time 2026-01-11T00:00:00Z

  # Inspect the remediation report
  cat ./output/remediation-report.json | jq '.summary'`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)

			hasViolations, err := stave.RunFixLoop(cmd.Context(), stave.FixLoopConfig{
				BeforeDir:     opts.BeforeDir,
				AfterDir:      opts.AfterDir,
				ControlsDir:   opts.ControlsDir,
				OutDir:        opts.OutDir,
				MaxUnsafe:     opts.MaxUnsafeRaw,
				EvalTime:      opts.EvalTimeRaw,
				Force:         gf.Force,
				AllowSymlinks: gf.AllowSymlinkOut,
				SanitizeIDs:   gf.Sanitize,
				PathMode:      string(gf.PathMode),
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped ("run fix loop"); preserve exit 4.
			}
			if hasViolations {
				return ui.ErrViolationsFound
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}
