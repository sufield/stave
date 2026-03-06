package initcmd

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/metadata"
)

var InitCmd = &cobra.Command{
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

  # 2. Create an S3-focused project with the mvp1-s3 profile.
  #    This adds S3-specific controls and snapshot directories.
  stave init --profile mvp1-s3

  # 3. Typical developer flow: create project dir, cd, then init.
  mkdir -p ~/projects/my-s3
  cd ~/projects/my-s3
  stave init --with-github-actions

  # 4. Optional automation flow: scaffold another directory from current shell.
  stave init --dir ./my-s3 --profile mvp1-s3 --capture-cadence hourly --force` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runInit,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	InitCmd.Flags().StringVarP(&initDir, "dir", "d", ".", "Directory where scaffold is created")
	InitCmd.Flags().StringVarP(&initProfile, "profile", "p", "", "Optional scaffold profile (supported: mvp1-s3)")
	InitCmd.Flags().BoolVar(&initDryRun, "dry-run", false, "Preview scaffold without creating files")
	InitCmd.Flags().BoolVar(&initWithGitHubActions, "with-github-actions", false, "Create a starter GitHub Actions workflow")
	InitCmd.Flags().StringVar(&initCaptureCadence, "capture-cadence", "daily", "Snapshot capture cadence template for scaffolded docs/workflows: daily or hourly")
}

var (
	quickstartReportPath string
	quickstartNowTime    string
)

var QuickstartCmd = &cobra.Command{
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
	Args:          cobra.NoArgs,
	RunE:          runQuickstart,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	QuickstartCmd.Flags().StringVar(&quickstartReportPath, "report", "stave-report.json", "Report artifact path")
	QuickstartCmd.Flags().StringVar(&quickstartNowTime, "now", "", "Override report generation time (RFC3339) for deterministic output")
}

var (
	demoFixtureName string
	demoReportPath  string
	demoNowTime     string
)

type demoReportRequest struct {
	Path        string
	Fixture     string
	Snapshot    asset.Snapshot
	Result      evaluation.Result
	Findings    []remediation.Finding
	GeneratedAt time.Time
	Overwrite   bool
}

var demoFastLaneControlIDs = []string{
	"CTL.S3.PUBLIC.001",
}

var DemoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run one-command hello-world safety loop",
	Long: `Demo executes the shortest possible Stave loop:

Snapshot -> Evaluate -> Finding -> Evidence -> Fix hint -> Report artifact

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
	RunE:          runDemo,
}

func init() {
	DemoCmd.Flags().StringVar(&demoFixtureName, "fixture", demoFixtureKnownBad, "Fixture to run: known-bad or known-good")
	DemoCmd.Flags().StringVar(&demoReportPath, "report", "./stave-report.json", "Report artifact path")
	DemoCmd.Flags().StringVar(&demoNowTime, "now", "", "Override report generation time (RFC3339) for deterministic output")
}

var (
	generateOut string
)

var GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate starter artifacts",
	Long:  "Generate creates minimal deterministic templates for controls and observations." + metadata.OfflineHelpSuffix,
	Args:  cobra.NoArgs,
}

var GenerateInvariantCmd = &cobra.Command{
	Use:           "control <name>",
	Short:         "Generate a canonical control template",
	Long:          "Generate control creates a ctrl.v1 YAML template in controls/." + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(1),
	RunE:          runGenerateControl,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var GenerateObservationCmd = &cobra.Command{
	Use:           "observation <name>",
	Short:         "Generate an observation template",
	Long:          "Generate observation creates an obs.v0.1 JSON template in observations/." + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(1),
	RunE:          runGenerateObservation,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	GenerateInvariantCmd.Flags().StringVar(&generateOut, "out", "", "Output file path (default: controls/<derived-id>.yaml)")
	GenerateObservationCmd.Flags().StringVar(&generateOut, "out", "", "Output file path (default: observations/<name>.json)")
	GenerateCmd.AddCommand(GenerateInvariantCmd)
	GenerateCmd.AddCommand(GenerateObservationCmd)
}
