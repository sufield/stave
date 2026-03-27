package initcmd

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/metadata"
)

// NewInitCmd constructs the init command with closure-scoped flags.
func NewInitCmd() *cobra.Command {
	var req InitRequest

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
  stave init --dir ./my-s3 --profile aws-s3 --capture-cadence hourly --force

Exit Codes:
  0   - Success
  2   - Input error
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example: `  mkdir myproject && cd myproject && stave init`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)
			runner := &InitRunner{
				Stdout:       cmd.OutOrStdout(),
				Stderr:       cmd.ErrOrStderr(),
				Force:        gf.Force,
				AllowSymlink: gf.AllowSymlinkOut,
				Quiet:        gf.Quiet,
			}
			return runner.Run(&req)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&req.Dir, "dir", "d", ".", "Directory where scaffold is created")
	cmd.Flags().StringVarP(&req.Profile, "profile", "p", "", "Optional scaffold profile (supported: aws-s3)")
	cmd.Flags().BoolVar(&req.DryRun, "dry-run", false, "Preview scaffold without creating files")
	cmd.Flags().BoolVar(&req.WithGitHubActions, "with-github-actions", false, "Create a starter GitHub Actions workflow")
	cmd.Flags().StringVar(&req.CaptureCadence, "capture-cadence", "daily", "Snapshot capture cadence template for scaffolded docs/workflows: daily or hourly")

	return cmd
}

// NewGenerateCmd constructs the generate command tree.
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
	var req GenerateRequest

	cmd := &cobra.Command{
		Use:   "control <name>",
		Short: "Generate a canonical control template",
		Long: `Generate control creates a ctrl.v1 YAML template in controls/.

Exit Codes:
  0   - Success
  2   - Input error
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave generate control my-control --out controls/my-control.yaml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Name = args[0]
			gf := cliflags.GetGlobalFlags(cmd)
			runner := &GenerateRunner{
				Out:          cmd.OutOrStdout(),
				Force:        gf.Force,
				Quiet:        gf.Quiet,
				AllowSymlink: gf.AllowSymlinkOut,
			}
			return runner.RunControl(req)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&req.Out, "out", "", "Output file path (default: controls/<derived-id>.yaml)")

	return cmd
}

func newGenerateObservationCmd() *cobra.Command {
	var req GenerateRequest

	cmd := &cobra.Command{
		Use:   "observation <name>",
		Short: "Generate an observation template",
		Long: `Generate observation creates an obs.v0.1 JSON template in observations/.

Exit Codes:
  0   - Success
  2   - Input error
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave generate observation my-obs --out observations/snap.json`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Name = args[0]
			gf := cliflags.GetGlobalFlags(cmd)
			runner := &GenerateRunner{
				Out:          cmd.OutOrStdout(),
				Force:        gf.Force,
				Quiet:        gf.Quiet,
				AllowSymlink: gf.AllowSymlinkOut,
			}
			return runner.RunObservation(req)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&req.Out, "out", "", "Output file path (default: observations/<name>.json)")

	return cmd
}
