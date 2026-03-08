package config

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

// ConfigOptions holds flags specific to config commands.
type ConfigOptions struct {
	Format string
}

type configCommand struct {
	rt   *ui.Runtime
	opts *ConfigOptions
}

// ConfigCmd keeps a package-level command for existing callers.
var ConfigCmd = NewConfigCmd(ui.NewRuntime(nil, nil))

// NewConfigCmd builds the config command tree with runtime-aware behavior.
func NewConfigCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.NewRuntime(nil, nil)
	}

	opts := &ConfigOptions{Format: "text"}
	cc := &configCommand{rt: rt, opts: opts}

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration commands",
		Long:  "Project configuration commands." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.AddCommand(
		cc.newGetCmd(),
		cc.newSetCmd(),
		cc.newDeleteCmd(),
		cc.newShowCmd(),
		cc.newExplainCmd(),
	)

	// Define once for all config subcommands.
	cmd.PersistentFlags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: text or json")

	return cmd
}

func (cc *configCommand) newGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a config value",
		Long: `Get prints a config value.

Supported keys:
  max_unsafe
  snapshot_retention
  default_retention_tier
  ci_failure_policy
  capture_cadence
  snapshot_filename_template
  snapshot_retention_tiers.<tier>` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return cmdutil.ConfigKeyCompletions(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cc.runConfigGet(cmd, args[0])
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func (cc *configCommand) newSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a project config value in stave.yaml",
		Long: `Set updates stave.yaml in the nearest project root, or creates one in the
current directory if none exists.

Supported keys:
  max_unsafe
  snapshot_retention
  default_retention_tier
  ci_failure_policy
  capture_cadence
  snapshot_filename_template
  snapshot_retention_tiers.<tier>` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(2),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return cmdutil.ConfigKeyCompletions(), cobra.ShellCompDirectiveNoFileComp
			}
			if len(args) == 1 && args[0] == "ci_failure_policy" {
				return []string{cmdutil.GatePolicyAny, cmdutil.GatePolicyNew, cmdutil.GatePolicyOverdue}, cobra.ShellCompDirectiveNoFileComp
			}
			if len(args) == 1 && args[0] == "capture_cadence" {
				return []string{"daily", "hourly"}, cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cc.runConfigSet(cmd, args[0], args[1])
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func (cc *configCommand) newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <key>",
		Short: "Remove a project config key (reverts to default)",
		Long: `Delete removes a key from stave.yaml, reverting it to the built-in default.
Supported keys match those of 'config set'.` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return cmdutil.ConfigKeyCompletions(), cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cc.runConfigDelete(cmd, args[0])
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func (cc *configCommand) newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show effective project configuration and value sources",
		Long: `Show prints the effective configuration values used by Stave and where each
value came from (environment variable, stave.yaml, user config, or built-in default).

Examples:
  stave config show
  stave config show --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cc.runConfigShow(cmd)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func (cc *configCommand) newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain",
		Short: "Explain resolved config values and sources",
		Long: `Explain is an alias of "stave config show". It prints effective values and
their resolution source (flag/env/project/user/default).` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cc.runConfigShow(cmd)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}
