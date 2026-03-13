package fix

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewFixCmd constructs the fix command.
func NewFixCmd() *cobra.Command {
	var (
		inputPath  string
		findingRef string
	)

	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Show machine-readable fix plan for a finding",
		Long: `Fix reads an evaluation artifact and prints deterministic remediation guidance
for a single finding. It never modifies user files.` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runner := NewRunner(compose.ActiveProvider(), ports.RealClock{})
			return runner.Fix(cmd.Context(), Request{
				InputPath:  inputPath,
				FindingRef: findingRef,
				Stdout:     cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&inputPath, "input", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&findingRef, "finding", "", "Finding selector: <control_id>@<asset_id> (required)")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("finding")

	return cmd
}

// NewFixLoopCmd constructs the fix-loop command.
func NewFixLoopCmd() *cobra.Command {
	var (
		beforeDir    string
		afterDir     string
		controlsDir  string
		maxUnsafeRaw string
		nowRaw       string
		allowUnknown bool
		outDir       string
	)
	allowUnknown = projconfig.Global().AllowUnknownInput()

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
		RunE: func(cmd *cobra.Command, _ []string) error {
			maxUnsafe, err := timeutil.ParseDurationFlag(maxUnsafeRaw, "--max-unsafe")
			if err != nil {
				return err
			}
			clock, err := compose.ResolveClock(nowRaw)
			if err != nil {
				return err
			}

			gf := cmdutil.GetGlobalFlags(cmd)
			runner := NewRunner(compose.ActiveProvider(), clock)
			runner.Sanitizer = gf.GetSanitizer()
			runner.FileOptions = cmdutil.FileOptions{
				Overwrite:     gf.Force,
				AllowSymlinks: gf.AllowSymlinkOut,
				DirPerms:      0o700,
			}

			return runner.Loop(cmd.Context(), LoopRequest{
				BeforeDir:    fsutil.CleanUserPath(beforeDir),
				AfterDir:     fsutil.CleanUserPath(afterDir),
				ControlsDir:  fsutil.CleanUserPath(controlsDir),
				OutDir:       fsutil.CleanUserPath(outDir),
				MaxUnsafe:    maxUnsafe,
				AllowUnknown: allowUnknown,
				Stdout:       cmd.OutOrStdout(),
				Stderr:       cmd.ErrOrStderr(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&beforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	f.StringVarP(&afterDir, "after", "a", "", "Path to after-remediation observations (required)")
	f.StringVarP(&controlsDir, "controls", "i", "controls", "Path to control definitions directory")
	f.StringVar(&maxUnsafeRaw, "max-unsafe", projconfig.Global().MaxUnsafe(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&nowRaw, "now", "", "Override current time (RFC3339). Required for deterministic output")
	f.BoolVar(&allowUnknown, "allow-unknown-input", allowUnknown, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown source types"))
	f.StringVar(&outDir, "out", "", "Write remediation artifacts to this directory")
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")

	return cmd
}
