package forge

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func newChainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chain",
		Short: "Author and validate custom chains",
		Long: `Tools for validating and testing custom compound chain definitions.

Subcommands:
  lint    Validate chain YAML against catalog and capability vocabulary
  test    Test a chain against a snapshot

Exit Codes:
  0   Valid / test complete
  1   Errors found
  2   Invalid input`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	var chainLintPath, controlsDir string
	lintCmd := &cobra.Command{
		Use:   "lint",
		Short: "Validate chain YAML",
		Long: `Validate a chain definition: member control IDs exist in catalog,
capability strings are valid, escalation threshold is correct.

Exit Codes:
  0   Valid
  1   Errors found
  2   Invalid input`,
		Example:       `  stave forge chain lint --chain chains/my-chain.yaml`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ForgeChainLint(chainLintPath, controlsDir)
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil && err == nil {
				return fmt.Errorf("write chain lint output: %w", werr)
			}
			return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
		},
	}
	lintCmd.Flags().StringVar(&chainLintPath, "chain", "", "path to chain YAML file (required)")
	lintCmd.Flags().StringVar(&controlsDir, "controls", "controls", "path to controls directory")
	_ = lintCmd.MarkFlagRequired("chain")
	cmd.AddCommand(lintCmd)

	return cmd
}
