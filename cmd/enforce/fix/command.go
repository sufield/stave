package fix

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

func NewFixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Show machine-readable fix plan for a finding",
		Long: `Fix reads an evaluation artifact and prints deterministic remediation guidance
for a single finding. It never modifies user files.` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          runFix,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(&fixFlags.inputPath, "input", "", "Path to evaluation JSON (required)")
	cmd.Flags().StringVar(&fixFlags.findingRef, "finding", "", "Finding selector: <control_id>@<asset_id> (required)")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("finding")
	return cmd
}

func NewFixLoopCmd() *cobra.Command {
	fixLoopFlags.allowUnknown = cmdutil.ResolveAllowUnknownInputDefault()
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
		Args:          cobra.NoArgs,
		RunE:          runFixLoop,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&fixLoopFlags.beforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	cmd.Flags().StringVarP(&fixLoopFlags.afterDir, "after", "a", "", "Path to after-remediation observations (required)")
	cmd.Flags().StringVarP(&fixLoopFlags.controlsDir, "controls", "i", "controls", "Path to control definitions directory")
	cmd.Flags().StringVar(&fixLoopFlags.maxUnsafe, "max-unsafe", cmdutil.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	cmd.Flags().StringVar(&fixLoopFlags.now, "now", "", "Override current time (RFC3339). Required for deterministic output")
	cmd.Flags().BoolVar(&fixLoopFlags.allowUnknown, "allow-unknown-input", fixLoopFlags.allowUnknown, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown source types"))
	cmd.Flags().StringVar(&fixLoopFlags.outDir, "out", "", "Write remediation artifacts to this directory")
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")
	return cmd
}
