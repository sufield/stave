package artifacts

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/internal/adapters/controls/builtin"
	appartifacts "github.com/sufield/stave/internal/app/artifacts"
	"github.com/sufield/stave/internal/app/catalog"
	packs "github.com/sufield/stave/internal/builtin/pack"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// NewControlsCmd constructs the controls command tree with closure-scoped flags.
func NewControlsCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "Work with control definitions",
		Long: `Controls groups commands for discovering and understanding control
definitions used by Stave.` + metadata.OfflineHelpSuffix,
		Example: `  stave controls list --controls ./controls
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls`,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newControlsListCmd(newCtlRepo))
	cmd.AddCommand(newControlsExplainCmd(newCtlRepo))
	cmd.AddCommand(newControlsAliasesCmd())
	cmd.AddCommand(newControlsAliasExplainCmd())

	return cmd
}

func newControlsListCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	cfg := catalog.ListConfig{}
	var filterPatterns []string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List control IDs and names",
		Long: `List loads controls from a directory and prints concise metadata.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave controls list --controls controls/s3 --format json
  stave controls list --built-in --filter aws/s3/severity:high+`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stdout := cmd.OutOrStdout()
			if cfg.ListPacks {
				return runListPacks(stdout, cfg)
			}
			provider, err := buildControlProvider(cfg, filterPatterns, newCtlRepo)
			if err != nil {
				return err
			}
			runner := &catalog.ListRunner{Provider: provider}
			rows, err := runner.Run(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			return appartifacts.FormatControlOutput(stdout, cfg, rows)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&cfg.Dir, "controls", "i", cliflags.DefaultControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVarP(&cfg.Columns, "columns", "c", "id,name,type", "Comma-separated columns: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&cfg.SortBy, "sort", "s", "id", "Sort column: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&cfg.Format, "format", "f", "text", "Output format: text, json, csv")
	cmd.Flags().BoolVar(&cfg.NoHeaders, "no-headers", false, "Hide headers for table/csv output")
	cmd.Flags().BoolVar(&cfg.UseBuiltIn, "built-in", false, "List built-in embedded controls instead of filesystem")
	cmd.Flags().BoolVar(&cfg.ListPacks, "packs", false, "List built-in control packs instead of controls")
	cmd.Flags().StringSliceVar(&filterPatterns, "filter", nil, "Filter controls by selector (e.g. aws/s3/severity:high+)")

	return cmd
}

func runListPacks(w io.Writer, cfg catalog.ListConfig) error {
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return err
	}
	items := reg.ListPacks()

	if cfg.Format == "json" {
		return jsonutil.WriteIndented(w, items)
	}

	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "No packs found.")
		return err
	}

	for _, p := range items {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", p.Name, p.Description); err != nil {
			return err
		}
	}
	return nil
}

func newControlsExplainCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	var controlsDir string

	cmd := &cobra.Command{
		Use:   "explain <control-id>",
		Short: "Explain a specific control",
		Long: `Explain loads one control and prints matched fields, rule expectations,
and a minimal observation snippet.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave controls explain CTL.S3.PUBLIC.001 --controls controls/s3`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, err := newCtlRepo()
			if err != nil {
				return fmt.Errorf("create control loader: %w", err)
			}
			explainer := diagnose.NewExplainerWithFinder(repo)
			result, err := explainer.Run(cmd.Context(), diagnose.ExplainRequest{
				ControlID:   kernel.ControlID(args[0]),
				ControlsDir: controlsDir,
			})
			if err != nil {
				return err
			}
			return diagnose.WriteExplainResult(cmd.OutOrStdout(), result, ui.OutputFormatText)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&controlsDir, "controls", cliflags.DefaultControlsDir, "Path to control definitions directory")

	return cmd
}

func newControlsAliasesCmd() *cobra.Command {
	var category string
	cmd := &cobra.Command{
		Use:   "aliases",
		Short: "List built-in semantic predicate aliases",
		Long: `List all built-in semantic predicate aliases that can be used in
control definitions via the unsafe_predicate_alias field. Optionally
filter by category.

Exit Codes:
  0    Success
  4    Internal error`,
		Example: `  stave controls aliases
  stave controls aliases --category Encryption`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			names := predicates.ListAliases(category)
			for _, name := range names {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), name); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&category, "category", "", "Filter by category (e.g. Encryption, Logging)")
	return cmd
}

func newControlsAliasExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "alias-explain <alias>",
		Short: "Show expanded predicate for an alias",
		Long: `Show the full predicate tree that a semantic alias expands to.
Use this to understand what an alias checks before using it in
a custom control definition.

Exit Codes:
  0    Success
  2    Unknown alias name
  4    Internal error`,
		Example: `  stave controls alias-explain s3.public_read
  stave controls alias-explain s3.encrypted_kms`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expanded, err := predicates.Resolve(strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			return jsonutil.WriteIndented(cmd.OutOrStdout(), map[string]any{
				"alias":    args[0],
				"expanded": expanded,
			})
		},
	}
}

// buildControlProvider constructs the right ControlProvider based on config.
// Built-in mode constructs the embedded registry with filter support.
// Filesystem mode delegates to the injected repo factory.
func buildControlProvider(cfg catalog.ListConfig, filters []string, newCtlRepo compose.CtlRepoFactory) (catalog.ControlProvider, error) {
	if cfg.UseBuiltIn {
		registry := builtin.NewRegistry(
			builtin.EmbeddedFS(), "embedded",
			builtin.WithAliasResolver(predicates.ResolverFunc()),
		)
		if len(filters) > 0 {
			selectors := make([]builtin.Selector, 0, len(filters))
			for _, pat := range filters {
				sel, err := builtin.ParseSelector(pat)
				if err != nil {
					return nil, fmt.Errorf("invalid filter %q: %w", pat, err)
				}
				selectors = append(selectors, sel)
			}
			return catalog.NewBuiltInProvider(func() ([]policy.ControlDefinition, error) {
				return registry.Filtered(selectors)
			}), nil
		}
		return catalog.NewBuiltInProvider(registry.All), nil
	}

	repo, err := newCtlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	return catalog.NewFSProvider(repo, cfg.Dir), nil
}
