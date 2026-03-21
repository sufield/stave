package config

import (
	"fmt"
	"io"
	"slices"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// ShowPresenter handles the formatting and output of the configuration summary.
type ShowPresenter struct {
	Stdout io.Writer
}

// Render writes the configuration summary in the requested format.
func (p *ShowPresenter) Render(out appconfig.EffectiveConfig, json bool) error {
	if json {
		return jsonutil.WriteIndented(p.Stdout, out)
	}
	return p.renderText(out)
}

func (p *ShowPresenter) renderText(out appconfig.EffectiveConfig) error {
	w := p.Stdout

	// Header
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
	if err := writeLines(w, lines...); err != nil {
		return err
	}

	// CLI defaults
	cliLines := []string{
		"\nCLI defaults:",
		fmt.Sprintf("  - output: %s (%s)", out.CLIOutput.Value, out.CLIOutput.Source),
		fmt.Sprintf("  - quiet: %s (%s)", out.CLIQuiet.Value, out.CLIQuiet.Source),
		fmt.Sprintf("  - sanitize: %s (%s)", out.CLISanitize.Value, out.CLISanitize.Source),
		fmt.Sprintf("  - path_mode: %s (%s)", out.CLIPathMode.Value, out.CLIPathMode.Source),
		fmt.Sprintf("  - allow_unknown_input: %s (%s)", out.CLIAllowUnknownInput.Value, out.CLIAllowUnknownInput.Source),
	}
	if err := writeLines(w, cliLines...); err != nil {
		return err
	}

	// Defined retention tiers
	if err := writeLines(w, "\nDefined retention tiers:"); err != nil {
		return err
	}
	for _, name := range sortedKeys(out.DefinedRetentionTiers) {
		tier := out.DefinedRetentionTiers[name]
		if _, err := fmt.Fprintf(w, "  - %s: older_than=%s keep_min=%d\n", name, tier.OlderThan, tier.EffectiveKeepMin()); err != nil {
			return err
		}
	}

	// Effective retention by tier
	if err := writeLines(w, "\nEffective retention by tier:"); err != nil {
		return err
	}
	for _, name := range sortedKeys(out.EffectiveRetentionByTier) {
		field := out.EffectiveRetentionByTier[name]
		if _, err := fmt.Fprintf(w, "  - %s: %s (%s)\n", name, field.Value, field.Source); err != nil {
			return err
		}
	}

	return nil
}

// buildShowOutput resolves the current effective configuration state.
func buildShowOutput(eval *appconfig.Evaluator) appconfig.EffectiveConfig {
	return eval.BuildEffectiveConfig()
}

func configFileLine(configFile string) string {
	if configFile == "" {
		return "Config file: (none found; using env/defaults)"
	}
	return fmt.Sprintf("Config file: %s", configFile)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func writeLines(w io.Writer, lines ...string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
