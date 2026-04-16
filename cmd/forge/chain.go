package forge

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/app/chainforge"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
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

	// chain lint
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
			return runChainLint(cmd.OutOrStdout(), chainLintPath, controlsDir)
		},
	}
	lintCmd.Flags().StringVar(&chainLintPath, "chain", "", "path to chain YAML file (required)")
	lintCmd.Flags().StringVar(&controlsDir, "controls", "controls", "path to controls directory")
	_ = lintCmd.MarkFlagRequired("chain")
	cmd.AddCommand(lintCmd)

	return cmd
}

func runChainLint(w io.Writer, chainPath, controlsDir string) error {
	data, err := fsutil.ReadFileLimited(chainPath)
	if err != nil {
		return fmt.Errorf("read chain: %w", err)
	}

	var chain policy.ChainDefinition
	if unmarshalErr := yaml.Unmarshal(data, &chain); unmarshalErr != nil {
		return fmt.Errorf("parse chain YAML: %w", unmarshalErr)
	}

	// Load all chains to validate, build catalog of control IDs.
	controlIDs := loadControlIDs(controlsDir)

	result := chainforge.LintChain(&chain, controlIDs)

	_, _ = fmt.Fprint(w, chainforge.FormatLint(result))
	fmt.Fprintf(w, "\n%d error(s), %d warning(s)\n", len(result.Errors), len(result.Warnings))

	if len(result.Errors) > 0 {
		return fmt.Errorf("%d chain lint error(s)", len(result.Errors))
	}
	return nil
}

func loadControlIDs(dir string) map[kernel.ControlID]bool {
	chains, err := ctlyaml.LoadChains(dir)
	_ = chains // we want control IDs, not chain IDs
	if err != nil {
		return nil
	}

	// Walk control files to collect IDs.
	paths, walkErr := collectControlPaths(dir)
	if walkErr != nil {
		return nil
	}

	ids := make(map[kernel.ControlID]bool, len(paths))
	for _, p := range paths {
		data, readErr := os.ReadFile(p) //nolint:gosec
		if readErr != nil {
			continue
		}
		ctl, unmarshalErr := ctlyaml.UnmarshalControlDefinition(data)
		if unmarshalErr != nil {
			continue
		}
		ids[ctl.ID] = true
	}
	return ids
}
