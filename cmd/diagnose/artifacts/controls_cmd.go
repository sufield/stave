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
	"github.com/sufield/stave/internal/app/catalogsearch"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	packs "github.com/sufield/stave/internal/builtin/pack"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/util/jsonutil"
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
	cmd.AddCommand(newControlsSearchCmd())
	cmd.AddCommand(newControlsQualityCmd(newCtlRepo))

	return cmd
}

func newControlsListCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	cfg := catalog.DiscoveryRequest{}
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
			if cfg.IncludePacks {
				return runListPacks(stdout, cfg)
			}
			provider, err := buildPolicySource(cfg, filterPatterns, newCtlRepo)
			if err != nil {
				return err
			}
			runner := &catalog.CatalogBrowser{Provider: provider}
			rows, err := runner.Browse(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			return appartifacts.FormatControlOutput(stdout, cfg, rows)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&cfg.PolicySource, "controls", "i", cliflags.DefaultControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVarP(&cfg.Fields, "columns", "c", "id,name,type", "Comma-separated columns: id,name,type,risk,domain")
	cmd.Flags().StringVarP(&cfg.OrderBy, "sort", "s", "id", "Sort column: id,name,type,risk,domain")
	cmd.Flags().StringVarP(&cfg.OutputFormat, "format", "f", "text", "Output format: text, json, csv")
	cmd.Flags().BoolVar(&cfg.HideHeaders, "no-headers", false, "Hide headers for table/csv output")
	cmd.Flags().BoolVar(&cfg.IncludeBuiltIn, "built-in", false, "List built-in embedded controls instead of filesystem")
	cmd.Flags().BoolVar(&cfg.IncludePacks, "packs", false, "List built-in control packs instead of controls")
	cmd.Flags().StringSliceVar(&filterPatterns, "filter", nil, "Filter controls by selector (e.g. aws/s3/severity:high+)")

	return cmd
}

func runListPacks(w io.Writer, cfg catalog.DiscoveryRequest) error {
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return err
	}
	items := reg.ListPacks()

	if appcontracts.OutputFormat(cfg.OutputFormat) == appcontracts.FormatJSON {
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
			ctlID, err := kernel.NewControlID(args[0])
			if err != nil {
				return fmt.Errorf("invalid control ID %q: %w", args[0], err)
			}

			explainer := diagnose.NewExplainerWithFinder(repo)
			result, err := explainer.Run(cmd.Context(), diagnose.ExplainRequest{
				ControlID:   ctlID,
				ControlsDir: controlsDir,
			})
			if err != nil {
				return err
			}
			return diagnose.WriteExplainResult(cmd.OutOrStdout(), result, appcontracts.FormatText)
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
			return renderAliasNames(cmd.OutOrStdout(), predicates.ListAliases(category))
		},
	}
	cmd.Flags().StringVar(&category, "category", "", "Filter by category (e.g. Encryption, Logging)")
	return cmd
}

// renderAliasNames writes one alias name per line.
func renderAliasNames(w io.Writer, names []string) error {
	for _, name := range names {
		if _, err := fmt.Fprintln(w, name); err != nil {
			return err
		}
	}
	return nil
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

func newControlsSearchCmd() *cobra.Command {
	var query, domain, severity, attackStage, format string

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search the built-in control catalog",
		Long: `Search controls by keyword, domain, severity, or attack stage.

Exit Codes:
  0    Success
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave controls search --query encryption
  stave controls search --domain s3 --severity critical
  stave controls search --query bucket --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store := builtin.NewControlStore(
				builtin.EmbeddedFS(), "embedded",
				builtin.WithAliasResolver(predicates.ResolverFunc()),
			)
			controls, err := store.All()
			if err != nil {
				return fmt.Errorf("load built-in controls: %w", err)
			}

			results := catalogsearch.Search(controls, catalogsearch.Filter{
				Query:       query,
				Domain:      domain,
				Severity:    severity,
				AttackStage: attackStage,
			})

			return renderControlSearch(cmd.OutOrStdout(), results, format)
		},
	}

	cmd.Flags().StringVar(&query, "query", "", "Search keywords (matches ID, name, description)")
	cmd.Flags().StringVar(&domain, "domain", "", "Filter by domain (e.g. s3, iam)")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter by severity (critical, high, medium, low)")
	cmd.Flags().StringVar(&attackStage, "attack-stage", "", "Filter by ATT&CK stage")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}

// renderControlSearch writes catalog-search results in the
// requested format. Takes an io.Writer so the caller owns the
// cobra boundary; this function stays off the cobra import graph.
func renderControlSearch(w io.Writer, results []catalogsearch.SearchResult, format string) error {
	if format == "json" {
		return jsonutil.WriteIndented(w, results)
	}
	if len(results) == 0 {
		_, err := fmt.Fprintln(w, "No matching controls found.")
		return err
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(w, "%-30s %-8s %s\n", r.ControlID, r.Severity, r.Name); err != nil {
			return err
		}
	}
	return nil
}

// buildPolicySource constructs the right ControlProvider based on config.
// Built-in mode constructs the embedded registry with filter support.
// Filesystem mode delegates to the injected repo factory.
func buildPolicySource(cfg catalog.DiscoveryRequest, filters []string, newCtlRepo compose.CtlRepoFactory) (catalog.PolicySource, error) {
	if cfg.IncludeBuiltIn {
		registry := builtin.NewControlStore(
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
			return catalog.NewLibrarySource(func() ([]policy.ControlDefinition, error) {
				return registry.Filtered(selectors)
			}), nil
		}
		return catalog.NewLibrarySource(registry.All), nil
	}

	repo, err := newCtlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	return catalog.NewWorkspaceSource(repo, cfg.PolicySource), nil
}
