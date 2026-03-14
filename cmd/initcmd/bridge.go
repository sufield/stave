package initcmd

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/initcmd/contextcmd"
	initenv "github.com/sufield/stave/cmd/initcmd/env"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/version"
)

// Constant aliases — shorthand for scaffold templates and tests.
const (
	defaultMaxUnsafeDuration = projconfig.DefaultMaxUnsafeDuration
	defaultSnapshotRetention = projconfig.DefaultSnapshotRetention
	defaultRetentionTier     = projconfig.DefaultRetentionTier
	defaultTierKeepMin       = projconfig.DefaultTierKeepMin
	defaultCIFailurePolicy   = string(projconfig.GatePolicyAny)
	projectConfigFile        = projconfig.ProjectConfigFile
)

// slugRegexp matches one or more non-alphanumeric characters for slug generation.
var slugRegexp = regexp.MustCompile(`[^a-z0-9]+`)

// GetRootCmd builds a minimal root *cobra.Command with initcmd subcommands
// attached. It is used by package-level tests that need to exercise commands
// via root.Execute() without importing the parent cmd package (which would
// create a circular dependency).
func GetRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "stave",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	p := root.PersistentFlags()
	p.String(cmdutil.FlagOutput, "text", "Output format: json or text")
	p.Bool(cmdutil.FlagQuiet, false, "Suppress output")
	p.CountP("verbose", "v", "Increase verbosity")
	p.Bool(cmdutil.FlagForce, false, "Allow overwrite operations")
	p.Bool(cmdutil.FlagSymlink, false, "Allow writing through symlinks")
	p.Bool(cmdutil.FlagSanitize, false, "Sanitize identifiers")
	p.String(cmdutil.FlagPathMode, "base", "Path rendering mode")
	p.String(cmdutil.FlagLogFile, "", "Log file path")
	p.Bool(cmdutil.FlagOffline, false, "Require offline execution")

	root.AddCommand(NewInitCmd())
	root.AddCommand(NewQuickstartCmd())
	root.AddCommand(NewDemoCmd())
	root.AddCommand(NewGenerateCmd())
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime(), projconfig.ConfigKeyService))
	root.AddCommand(contextcmd.NewContextCmd())
	root.AddCommand(initenv.NewEnvCmd())
	root.AddCommand(alias.NewCmd(root))

	return root
}

// GetVersion returns the CLI version string.
func GetVersion() string { return version.Version }

// ---------------------------------------------------------------------------
// Utility helpers shared across init sub-files.
// ---------------------------------------------------------------------------

func normalizeTemplate(s string) string {
	s = strings.TrimLeft(s, "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

func onboardingCommandError(err error, runLine string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w\nRun: %s", err, runLine)
}

func readBool(m map[string]any, keys ...string) bool {
	if len(keys) == 0 {
		return false
	}
	var cur any = m
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur, ok = obj[k]
		if !ok {
			return false
		}
	}
	b, ok := cur.(bool)
	return ok && b
}

func controlIDFromName(name string) string {
	f := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}
	parts := strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(name)), f)

	if len(parts) == 0 {
		return "CTL.GENERATED.SAMPLE.001"
	}
	domain := parts[0]
	category := "SAMPLE"
	if len(parts) > 1 {
		category = strings.Join(parts[1:], "_")
	}
	return fmt.Sprintf("CTL.%s.%s.001", domain, category)
}

func sanitizeSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugRegexp.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "snapshot"
	}
	return s
}
