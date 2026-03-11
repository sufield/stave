package config

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

type configKeyValueOutput struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
	Path   string `json:"path,omitempty"`
}

type configResolvedField = configservice.ResolvedField
type configShowOutput = configservice.EffectiveConfig

func buildConfigShowOutput() configShowOutput {
	cfg, cfgPath, hasCfg := projconfig.FindProjectConfigWithPath()

	retTier := projconfig.ResolveRetentionTierWithSource(cfg, cfgPath)
	out := configShowOutput{
		DefaultRetentionTier:     toConfigField(retTier),
		MaxUnsafe:                toConfigField(projconfig.ResolveMaxUnsafeWithSource(cfg, cfgPath)),
		SnapshotRetention:        toConfigField(projconfig.ResolveSnapshotRetentionWithSource(cfg, cfgPath, retTier.Value)),
		CIFailurePolicy:          toConfigField(projconfig.ResolveCIFailurePolicyWithSource(cfg, cfgPath)),
		CLIOutput:                toConfigField(projconfig.ResolveCLIOutputWithSource()),
		CLIQuiet:                 toConfigField(projconfig.ResolveCLIQuietWithSource().ToConfigValue()),
		CLISanitize:              toConfigField(projconfig.ResolveCLISanitizeWithSource().ToConfigValue()),
		CLIPathMode:              toConfigField(projconfig.ResolveCLIPathModeWithSource()),
		CLIAllowUnknownInput:     toConfigField(projconfig.ResolveCLIAllowUnknownInputWithSource().ToConfigValue()),
		DefinedRetentionTiers:    resolveDefinedRetentionTiers(cfg),
		EffectiveRetentionByTier: map[string]configResolvedField{},
	}
	applyProjectConfigLocation(&out, hasCfg, cfgPath)
	if _, userPath, ok := projconfig.FindUserConfigWithPath(); ok {
		out.UserConfigFile = userPath
	}
	for tier := range out.DefinedRetentionTiers {
		out.EffectiveRetentionByTier[tier] = toConfigField(projconfig.ResolveSnapshotRetentionWithSource(cfg, cfgPath, tier))
	}
	return out
}

func applyProjectConfigLocation(out *configShowOutput, hasCfg bool, cfgPath string) {
	if !hasCfg {
		return
	}
	out.ConfigFile = cfgPath
	out.ProjectRoot = filepath.Dir(cfgPath)
}

func resolveDefinedRetentionTiers(cfg *projconfig.ProjectConfig) map[string]configservice.RetentionTierConfig {
	if tiers := projconfig.ResolveDefinedRetentionTiers(cfg); len(tiers) > 0 {
		out := make(map[string]configservice.RetentionTierConfig, len(tiers))
		for name, tier := range tiers {
			out[name] = configservice.RetentionTierConfig{OlderThan: tier.OlderThan, KeepMin: tier.KeepMin}
		}
		return out
	}
	return map[string]configservice.RetentionTierConfig{
		projconfig.DefaultRetentionTier: {OlderThan: projconfig.DefaultSnapshotRetention, KeepMin: projconfig.DefaultTierKeepMin},
	}
}

func writeConfigShowJSON(cmd *cobra.Command, out configShowOutput) error {
	return jsonutil.WriteIndented(cmd.OutOrStdout(), out)
}

func toConfigField(v projconfig.ResolvedConfigValue) configResolvedField {
	return configResolvedField{Value: v.Value, Source: v.Source}
}

func writeConfigShowText(cmd *cobra.Command, out configShowOutput) error {
	w := cmd.OutOrStdout()
	if err := writeConfigShowHeader(w, out); err != nil {
		return err
	}
	if err := writeConfigShowCLIDefaults(w, out); err != nil {
		return err
	}
	if err := writeDefinedRetentionTierText(w, out.DefinedRetentionTiers); err != nil {
		return err
	}
	return writeEffectiveRetentionText(w, out.EffectiveRetentionByTier)
}

func writeConfigShowHeader(w io.Writer, out configShowOutput) error {
	lines := []string{
		"Effective Configuration",
		"-----------------------",
		configFileLine(out.ConfigFile),
	}
	if out.UserConfigFile != "" {
		lines = append(lines, fmt.Sprintf("User config: %s", out.UserConfigFile))
	}
	lines = append(lines,
		fmt.Sprintf("max_unsafe: %s (%s)", out.MaxUnsafe.Value, out.MaxUnsafe.Source),
		fmt.Sprintf("snapshot_retention: %s (%s)", out.SnapshotRetention.Value, out.SnapshotRetention.Source),
		fmt.Sprintf("default_retention_tier: %s (%s)", out.DefaultRetentionTier.Value, out.DefaultRetentionTier.Source),
		fmt.Sprintf("ci_failure_policy: %s (%s)", out.CIFailurePolicy.Value, out.CIFailurePolicy.Source),
	)
	return writeLines(w, lines...)
}

func configFileLine(configFile string) string {
	if configFile == "" {
		return "Config file: (none found; using env/defaults)"
	}
	return fmt.Sprintf("Config file: %s", configFile)
}

func writeConfigShowCLIDefaults(w io.Writer, out configShowOutput) error {
	lines := []string{
		"\nCLI defaults:",
		fmt.Sprintf("  - output: %s (%s)", out.CLIOutput.Value, out.CLIOutput.Source),
		fmt.Sprintf("  - quiet: %s (%s)", out.CLIQuiet.Value, out.CLIQuiet.Source),
		fmt.Sprintf("  - sanitize: %s (%s)", out.CLISanitize.Value, out.CLISanitize.Source),
		fmt.Sprintf("  - path_mode: %s (%s)", out.CLIPathMode.Value, out.CLIPathMode.Source),
		fmt.Sprintf("  - allow_unknown_input: %s (%s)", out.CLIAllowUnknownInput.Value, out.CLIAllowUnknownInput.Source),
	}
	return writeLines(w, lines...)
}

func writeDefinedRetentionTierText(w io.Writer, tiers map[string]configservice.RetentionTierConfig) error {
	if err := writeLines(w, "\nDefined retention tiers:"); err != nil {
		return err
	}
	for _, name := range sortedConfigKeys(tiers) {
		tier := tiers[name]
		keepMin := projconfig.RetentionTierConfig{KeepMin: tier.KeepMin}.EffectiveKeepMin()
		if _, err := fmt.Fprintf(w, "  - %s: older_than=%s keep_min=%d\n", name, tier.OlderThan, keepMin); err != nil {
			return err
		}
	}
	return nil
}

func writeEffectiveRetentionText(w io.Writer, tiers map[string]configResolvedField) error {
	if err := writeLines(w, "\nEffective retention by tier:"); err != nil {
		return err
	}
	for _, name := range sortedConfigKeys(tiers) {
		field := tiers[name]
		if _, err := fmt.Fprintf(w, "  - %s: %s (%s)\n", name, field.Value, field.Source); err != nil {
			return err
		}
	}
	return nil
}

func sortedConfigKeys[V any](items map[string]V) []string {
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func writeLines(w io.Writer, lines ...string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
