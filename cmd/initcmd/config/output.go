package config

import (
	"fmt"
	"io"
	"slices"

	appconfig "github.com/sufield/stave/internal/app/config"
)

// ShowPresenter holds the text layout for the configuration summary.
// Format dispatch lives in the typed NewShowRenderer factory
// (renderer.go); ShowTextRenderer delegates here for the text path.
type ShowPresenter struct {
	Stdout io.Writer
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
		lines = append(lines, "User config: "+out.UserConfigFile)
	}
	lines = append(lines,
		fmt.Sprintf("max_unsafe: %s (%s)", out.MaxUnsafeDuration.Value, out.MaxUnsafeDuration.Source),
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
	}
	if err := writeLines(w, cliLines...); err != nil {
		return err
	}

	return nil
}

// buildShowOutput resolves the current effective configuration state.
func buildShowOutput(eval *appconfig.GovernanceResolver) appconfig.EffectiveConfig {
	return eval.BuildEffectiveConfig()
}

func configFileLine(configFile string) string {
	if configFile == "" {
		return "Config file: (none found; using env/defaults)"
	}
	return "Config file: " + configFile
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
