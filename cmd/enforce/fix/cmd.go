package fix

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/fileout"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// NewFixCmd constructs the fix command.
func NewFixCmd(newCELEvaluator compose.CELEvaluatorFactory) *cobra.Command {
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
  130 - Interrupted (SIGINT)

Examples:
  # Show fix plan for a specific finding
  stave ci fix --input output/evaluation.json --finding CTL.S3.PUBLIC.001@res:aws:s3:bucket:my-bucket

  # Pipe to jq for structured inspection
  stave ci fix --input output/evaluation.json --finding CTL.S3.PUBLIC.001@res:aws:s3:bucket:my-bucket | jq .` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			celEval, err := newCELEvaluator()
			if err != nil {
				return err
			}
			runner := NewRunner(celEval, ports.RealClock{})
			return runner.Run(cmd.Context(), Request{
				InputPath:  opts.InputPath,
				FindingRef: opts.FindingRef,
				Stdout:     cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}

// NewFixLoopCmd constructs the fix-loop command.
func NewFixLoopCmd(newCELEvaluator compose.CELEvaluatorFactory, newCtlRepo compose.CtlRepoFactory, newObsRepo compose.ObsRepoFactory) *cobra.Command {
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
  3   - Remaining or introduced violations exist

Examples:
  # 1. Run a full fix-loop comparing before and after observations.
  stave ci fix-loop --before ./obs-before --after ./obs-after --controls ./controls --out ./output --now 2026-01-11T00:00:00Z

  # 2. Run in CI with a strict 72-hour threshold.
  stave ci fix-loop --before ./obs-before --after ./obs-after --controls ./controls --out ./output --max-unsafe 72h --now 2026-01-11T00:00:00Z

  # 3. Inspect the remediation report.
  cat ./output/remediation-report.json | jq '.summary'

    Sample output:
      { "before_violations": 5, "after_violations": 2, "resolved": 3, "remaining": 2, "introduced": 0 }` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			maxUnsafe, err := cliflags.ParseDurationFlag(opts.MaxUnsafeRaw, "--max-unsafe")
			if err != nil {
				return err
			}
			clock, err := compose.ResolveClock(opts.NowRaw)
			if err != nil {
				return err
			}

			gf := cliflags.GetGlobalFlags(cmd)
			celEval, celErr := newCELEvaluator()
			if celErr != nil {
				return celErr
			}
			runner := NewRunner(celEval, clock)
			runner.NewCtlRepo = newCtlRepo
			runner.NewObsRepo = newObsRepo
			runner.Sanitizer = gf.GetSanitizer()
			runner.FileOptions = fileout.FileOptions{
				Overwrite:     gf.Force,
				AllowSymlinks: gf.AllowSymlinkOut,
				DirPerms:      0o700,
			}

			return runner.Loop(cmd.Context(), LoopRequest{
				BeforeDir:         opts.BeforeDir,
				AfterDir:          opts.AfterDir,
				ControlsDir:       opts.ControlsDir,
				OutDir:            opts.OutDir,
				MaxUnsafeDuration: maxUnsafe,
				AllowUnknown:      opts.AllowUnknown,
				Stdout:            cmd.OutOrStdout(),
				Stderr:            cmd.ErrOrStderr(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}
