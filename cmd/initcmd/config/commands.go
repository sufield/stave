package config

import (
	"log/slog"

	"github.com/spf13/cobra"
	appconfig "github.com/sufield/stave/internal/app/config"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/initcmd/contextcmd"
	initenv "github.com/sufield/stave/cmd/initcmd/env"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

// NewConfigCmd builds the config command tree with runtime-aware behavior.
//
// rt is the output runtime; pass ui.DefaultRuntime() to use the process's
// standard streams. If nil, DefaultRuntime() is used automatically.
func NewConfigCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.DefaultRuntime()
	}

	var format string

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration commands",
		Long:  "Project configuration commands." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.PersistentFlags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	cmd.AddCommand(
		newGetCmd(rt, &format),
		newSetCmd(rt, &format),
		newDeleteCmd(rt, &format),
		newShowCmd(rt, &format),
		newExplainCmd(rt, &format),
		contextcmd.NewContextCmd(),
		initenv.NewEnvCmd(),
	)

	return cmd
}

func newRunner(rt *ui.Runtime, cmd *cobra.Command) *Runner {
	return &Runner{
		RT:     rt,
		Stdout: cmd.OutOrStdout(),
		Stderr: cmd.ErrOrStderr(),
	}
}

func mutationOptsFrom(gf cmdutil.GlobalFlags, format ui.OutputFormat) MutationOpts {
	return MutationOpts{
		Format:       format,
		Force:        gf.Force,
		IsTTY:        ui.IsStderrTTY(),
		AllowSymlink: gf.AllowSymlinkOut,
		Quiet:        gf.Quiet,
	}
}

// configKeyCompletions returns config key completions including retention tier
// variants from the project config.
func configKeyCompletions() []string {
	tiers := []string{appconfig.DefaultRetentionTier}

	if cfg, ok, cfgErr := projconfig.FindProjectConfig(); cfgErr != nil {
		slog.Warn("failed to load project config for completions", "error", cfgErr)
	} else if ok {
		if t := appconfig.NormalizeTier(cfg.RetentionTier); t != "" {
			tiers = append(tiers, t)
		}
		for tier := range cfg.RetentionTiers {
			if t := appconfig.NormalizeTier(tier); t != "" {
				tiers = append(tiers, t)
			}
		}
	}

	return appconfig.BuildKeyCompletions(tiers)
}

func newGetCmd(rt *ui.Runtime, format *string) *cobra.Command {
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
			return configKeyCompletions(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, *format)
			if err != nil {
				return err
			}
			runner := newRunner(rt, cmd)
			return runner.Get(cmd.Context(), GetRequest{Key: args[0], Format: fmtValue})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func newSetCmd(rt *ui.Runtime, format *string) *cobra.Command {
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
				return configKeyCompletions(), cobra.ShellCompDirectiveNoFileComp
			}
			if len(args) == 1 && args[0] == "ci_failure_policy" {
				return []string{string(appconfig.GatePolicyAny), string(appconfig.GatePolicyNew), string(appconfig.GatePolicyOverdue)}, cobra.ShellCompDirectiveNoFileComp
			}
			if len(args) == 1 && args[0] == "capture_cadence" {
				return []string{"daily", "hourly"}, cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, *format)
			if err != nil {
				return err
			}
			gf := cmdutil.GetGlobalFlags(cmd)
			runner := newRunner(rt, cmd)
			return runner.Set(cmd.Context(), SetRequest{
				Key:   args[0],
				Value: args[1],
			}, mutationOptsFrom(gf, fmtValue))
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func newDeleteCmd(rt *ui.Runtime, format *string) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <key>",
		Short: "Remove a project config key (reverts to default)",
		Long: `Delete removes a key from stave.yaml, reverting it to the built-in default.
Supported keys match those of 'config set'.` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return configKeyCompletions(), cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, *format)
			if err != nil {
				return err
			}
			gf := cmdutil.GetGlobalFlags(cmd)
			runner := newRunner(rt, cmd)
			return runner.Delete(cmd.Context(), DeleteRequest{
				Key: args[0],
			}, mutationOptsFrom(gf, fmtValue))
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func newShowCmd(rt *ui.Runtime, format *string) *cobra.Command {
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
			fmtValue, err := compose.ResolveFormatValue(cmd, *format)
			if err != nil {
				return err
			}
			runner := newRunner(rt, cmd)
			return runner.Show(cmd.Context(), fmtValue)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func newExplainCmd(rt *ui.Runtime, format *string) *cobra.Command {
	return &cobra.Command{
		Use:   "explain",
		Short: "Explain resolved config values and sources",
		Long: `Explain is an alias of "stave config show". It prints effective values and
their resolution source (flag/env/project/user/default).` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, *format)
			if err != nil {
				return err
			}
			runner := newRunner(rt, cmd)
			return runner.Show(cmd.Context(), fmtValue)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}
