package artifacts

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/internal/adapters/controls/builtin"
	appartifacts "github.com/sufield/stave/internal/app/artifacts"
	"github.com/sufield/stave/internal/app/catalog"
	packs "github.com/sufield/stave/internal/builtin/pack"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// NewControlsCmd constructs the controls command tree with closure-scoped flags.
func NewControlsCmd(p *compose.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "Work with control definitions",
		Long: `Controls groups commands for discovering and understanding control
definitions used by Stave.

Examples:
  stave controls list --controls ./controls
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newControlsListCmd(p.NewControlRepo))
	cmd.AddCommand(newControlsExplainCmd(p.NewControlRepo))
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

Examples:
  stave controls list --controls ./controls
  stave controls list --controls ./controls --format json
  stave controls list --controls ./controls --format csv --columns id,name
  stave controls list --built-in --filter aws/s3/severity:high+` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stdout := cmd.OutOrStdout()
			if cfg.ListPacks {
				return runListPacks(stdout, cfg)
			}
			rows, err := listControlRows(cmd.Context(), newCtlRepo, cfg, filterPatterns)
			if err != nil {
				return err
			}
			return appartifacts.FormatControlOutput(stdout, cfg, rows)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&cfg.Dir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&cfg.Columns, "columns", "c", "id,name,type", "Comma-separated columns: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&cfg.SortBy, "sort", "s", "id", "Sort column: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&cfg.Format, "format", "f", "text", "Output format: text, json, csv")
	cmd.Flags().BoolVar(&cfg.NoHeaders, "no-headers", false, "Hide headers for table/csv output")
	cmd.Flags().BoolVar(&cfg.UseBuiltIn, "built-in", false, "List built-in embedded controls instead of filesystem")
	cmd.Flags().BoolVar(&cfg.ListPacks, "packs", false, "List built-in control packs instead of controls")
	cmd.Flags().StringSliceVar(&filterPatterns, "filter", nil, "Filter controls by selector (e.g. aws/s3/severity:high+)")

	return cmd
}

func listControlRows(ctx context.Context, newCtlRepo compose.CtlRepoFactory, cfg catalog.ListConfig, filterPatterns []string) ([]catalog.ControlRow, error) {
	if cfg.UseBuiltIn {
		registry := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded")

		var controls []policy.ControlDefinition
		var err error

		if len(filterPatterns) > 0 {
			selectors := make([]builtin.Selector, 0, len(filterPatterns))
			for _, pat := range filterPatterns {
				sel, parseErr := builtin.ParseSelector(pat)
				if parseErr != nil {
					return nil, fmt.Errorf("invalid filter %q: %w", pat, parseErr)
				}
				selectors = append(selectors, sel)
			}
			controls, err = registry.Filtered(selectors)
		} else {
			controls, err = registry.All()
		}
		if err != nil {
			return nil, fmt.Errorf("load built-in controls: %w", err)
		}
		rows := catalog.ToRows(controls)
		if err := catalog.SortRows(rows, cfg.SortBy); err != nil {
			return nil, err
		}
		return rows, nil
	}

	repo, err := newCtlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	return (&catalog.ListRunner{Repo: repo}).Run(ctx, cfg)
}

func runListPacks(w interface{ Write([]byte) (int, error) }, cfg catalog.ListConfig) error {
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return err
	}
	items := reg.ListPacks()

	if strings.ToLower(strings.TrimSpace(cfg.Format)) == "json" {
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

Examples:
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			explainer := diagnose.NewExplainer(newCtlRepo)
			return explainer.Run(cmd.Context(), diagnose.ExplainRequest{
				ControlID:   args[0],
				ControlsDir: controlsDir,
				Format:      ui.OutputFormatText,
				Stdout:      cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&controlsDir, "controls", "controls/s3", "Path to control definitions directory")

	return cmd
}

func newControlsAliasesCmd() *cobra.Command {
	var category string
	cmd := &cobra.Command{
		Use:   "aliases",
		Short: "List built-in semantic predicate aliases",
		Args:  cobra.NoArgs,
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
		Args:  cobra.ExactArgs(1),
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
