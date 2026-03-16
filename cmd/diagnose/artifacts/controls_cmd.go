package artifacts

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// NewControlsCmd constructs the controls command tree with closure-scoped flags.
func NewControlsCmd() *cobra.Command {
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

	cmd.AddCommand(newControlsListCmd())
	cmd.AddCommand(newControlsExplainCmd())
	cmd.AddCommand(newControlsAliasesCmd())
	cmd.AddCommand(newControlsAliasExplainCmd())

	return cmd
}

func newControlsListCmd() *cobra.Command {
	cfg := ListConfig{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List control IDs and names",
		Long: `List loads controls from a directory and prints concise metadata.

Examples:
  stave controls list --controls ./controls
  stave controls list --controls ./controls --format json
  stave controls list --controls ./controls --format csv --columns id,name` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.Stdout = cmd.OutOrStdout()
			runner := &ListRunner{Provider: compose.ActiveProvider()}
			return runner.Run(cmd.Context(), cfg)
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

	return cmd
}

func newControlsExplainCmd() *cobra.Command {
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
			explainer := diagnose.NewExplainer(compose.ActiveProvider())
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
	return &cobra.Command{
		Use:   "aliases",
		Short: "List built-in semantic predicate aliases",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			names := predicates.ListAliases()
			for _, name := range names {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), name); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newControlsAliasExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "alias-explain <alias>",
		Short: "Show expanded predicate for an alias",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expanded, ok := predicates.Resolve(strings.TrimSpace(args[0]))
			if !ok {
				return fmt.Errorf("unknown alias %q (available: %s)", args[0], strings.Join(predicates.ListAliases(), ", "))
			}
			return jsonutil.WriteIndented(cmd.OutOrStdout(), map[string]any{
				"alias":    args[0],
				"expanded": expanded,
			})
		},
	}
}
