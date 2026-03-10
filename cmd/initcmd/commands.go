package initcmd

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/metadata"
)

// NewInitCmd constructs the init command with closure-scoped flags.
func NewInitCmd() *cobra.Command {
	var flags initFlagsType

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a starter Stave project structure",
		Long: `Init creates a minimal project layout for Stave workflows, including folders
for runtime controls, raw snapshots, normalized observations,
and output artifacts.

It also writes starter templates and a .gitignore to avoid checking in raw/sensitive
files by default.

Examples:
  # 1. Create a minimal project scaffold in the current directory.
  stave init

  # 2. Create an S3-focused project with the aws-s3 profile.
  #    This adds S3-specific controls and snapshot directories.
  stave init --profile aws-s3

  # 3. Typical developer flow: create project dir, cd, then init.
  mkdir -p ~/projects/my-s3
  cd ~/projects/my-s3
  stave init --with-github-actions

  # 4. Optional automation flow: scaffold another directory from current shell.
  stave init --dir ./my-s3 --profile aws-s3 --capture-cadence hourly --force` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&flags.dir, "dir", "d", ".", "Directory where scaffold is created")
	cmd.Flags().StringVarP(&flags.profile, "profile", "p", "", "Optional scaffold profile (supported: aws-s3)")
	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Preview scaffold without creating files")
	cmd.Flags().BoolVar(&flags.withGitHubActions, "with-github-actions", false, "Create a starter GitHub Actions workflow")
	cmd.Flags().StringVar(&flags.captureCadence, "capture-cadence", "daily", "Snapshot capture cadence template for scaffolded docs/workflows: daily or hourly")

	return cmd
}

// NewQuickstartCmd constructs the quickstart command with closure-scoped flags.
func NewQuickstartCmd() *cobra.Command {
	var flags quickstartFlagsType

	cmd := &cobra.Command{
		Use:   "quickstart",
		Short: "Run the fastest path to a first finding",
		Long: `Quickstart detects snapshot files in the current working directory and
executes the fast-lane control check immediately.

Behavior:
  1. Search ./stave.snapshot, ./observations, and current directory for snapshots.
  2. If an observation snapshot is found, evaluate it with the fast lane.
  3. If none is found, run the built-in demo fixture automatically.
  4. Print one top finding and write ./stave-report.json.

Examples:
  stave quickstart
  mkdir -p stave.snapshot && cp snapshot.json stave.snapshot/
  stave quickstart --now 2026-01-15T00:00:00Z
  stave quickstart` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runQuickstart(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&flags.reportPath, "report", "stave-report.json", "Report artifact path")
	cmd.Flags().StringVar(&flags.nowTime, "now", "", "Override report generation time (RFC3339) for deterministic output")

	return cmd
}

type demoReportRequest struct {
	Path         string
	Fixture      string
	Snapshot     asset.Snapshot
	Result       evaluation.Result
	Findings     []remediation.Finding
	GeneratedAt  time.Time
	Overwrite    bool
	AllowSymlink bool
}

var demoFastLaneControlIDs = []string{
	"CTL.S3.PUBLIC.001",
}

// NewDemoCmd constructs the demo command with closure-scoped flags.
func NewDemoCmd() *cobra.Command {
	var flags demoFlagsType

	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Run one-command hello-world safety loop",
		Long: `Demo executes the shortest possible Stave loop:

Snapshot -> Apply -> Finding -> Evidence -> Fix hint -> Report artifact

It loads a tiny built-in fixture, runs a fast-lane control set, prints one
clear result, and writes a small report file.

Examples:
  stave demo
  stave demo --fixture known-good
  stave demo --now 2026-01-15T00:00:00Z
  stave demo --report ./stave-report.json` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDemo(cmd, &flags)
		},
	}

	cmd.Flags().StringVar(&flags.fixtureName, "fixture", demoFixtureKnownBad, "Fixture to run: known-bad or known-good")
	cmd.Flags().StringVar(&flags.reportPath, "report", "./stave-report.json", "Report artifact path")
	cmd.Flags().StringVar(&flags.nowTime, "now", "", "Override report generation time (RFC3339) for deterministic output")

	return cmd
}

// NewGenerateCmd constructs the generate command tree with closure-scoped flags.
func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate starter artifacts",
		Long:  "Generate creates minimal deterministic templates for controls and observations." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.AddCommand(newGenerateControlCmd())
	cmd.AddCommand(newGenerateObservationCmd())

	return cmd
}

func newGenerateControlCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "control <name>",
		Short: "Generate a canonical control template",
		Long:  "Generate control creates a ctrl.v1 YAML template in controls/." + metadata.OfflineHelpSuffix,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerateControl(cmd, args, out)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&out, "out", "", "Output file path (default: controls/<derived-id>.yaml)")

	return cmd
}

func newGenerateObservationCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "observation <name>",
		Short: "Generate an observation template",
		Long:  "Generate observation creates an obs.v0.1 JSON template in observations/." + metadata.OfflineHelpSuffix,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenerateObservation(cmd, args, out)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&out, "out", "", "Output file path (default: observations/<name>.json)")

	return cmd
}
