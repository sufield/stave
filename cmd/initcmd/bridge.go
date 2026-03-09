package initcmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/initcmd/contextcmd"
	initenv "github.com/sufield/stave/cmd/initcmd/env"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/version"
)

// Constant aliases — shorthand for scaffold templates and tests.
const (
	defaultMaxUnsafeDuration = cmdutil.DefaultMaxUnsafeDuration
	defaultSnapshotRetention = cmdutil.DefaultSnapshotRetention
	defaultRetentionTier     = cmdutil.DefaultRetentionTier
	defaultTierKeepMin       = cmdutil.DefaultTierKeepMin
	defaultCIFailurePolicy   = cmdutil.DefaultCIFailurePolicy
	projectConfigFile        = cmdutil.ProjectConfigFile
)

// Package-level globals — set externally or read from cobra flags.
var (
	globalForce           bool
	globalQuiet           bool
	globalAllowSymlinkOut bool
)

// SetGlobals allows the parent package to inject global flag values.
func SetGlobals(force, quiet, allowSymlink bool) {
	globalForce = force
	globalQuiet = quiet
	globalAllowSymlinkOut = allowSymlink
}

// GetRootCmd builds a minimal root *cobra.Command with initcmd subcommands
// attached. It is used by package-level tests that need to exercise commands
// via root.Execute() without importing the parent cmd package (which would
// create a circular dependency).
func GetRootCmd() *cobra.Command {
	globalForce = false
	globalQuiet = false
	globalAllowSymlinkOut = false

	root := &cobra.Command{
		Use:           "stave",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("output", "text", "Output format: json or text")
	root.PersistentFlags().BoolVar(&globalQuiet, "quiet", false, "Suppress output")
	root.PersistentFlags().CountP("verbose", "v", "Increase verbosity")
	root.PersistentFlags().BoolVar(&globalForce, "force", false, "Allow overwrite operations")
	root.PersistentFlags().BoolVar(&globalAllowSymlinkOut, "allow-symlink-output", false, "Allow writing through symlinks")
	root.PersistentFlags().Bool("sanitize", false, "Sanitize identifiers")
	root.PersistentFlags().String("path-mode", "base", "Path rendering mode")
	root.PersistentFlags().String("log-file", "", "Log file path")
	root.PersistentFlags().Bool("require-offline", false, "Require offline execution")
	root.AddCommand(NewInitCmd())
	root.AddCommand(NewQuickstartCmd())
	root.AddCommand(NewDemoCmd())
	root.AddCommand(NewGenerateCmd())
	root.AddCommand(initconfig.NewConfigCmd(ui.NewRuntime(nil, nil)))
	root.AddCommand(contextcmd.NewContextCmd())
	root.AddCommand(initenv.NewEnvCmd())
	root.AddCommand(initalias.NewAliasCmd())
	return root
}

// GetVersion returns the CLI version string.
func GetVersion() string { return version.Version }

// evalOutput returns os.Stdout or io.Discard based on quiet mode.
func evalOutput() io.Writer {
	if globalQuiet {
		return io.Discard
	}
	return os.Stdout
}

// ---------------------------------------------------------------------------
// Utility helpers shared across init sub-files.
// ---------------------------------------------------------------------------

func normalizeTemplate(s string) string {
	s = strings.TrimLeft(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

func onboardingCommandError(err error, runLine string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v\nRun: %s", err, runLine)
}

func readBool(m map[string]any, keys ...string) bool {
	if len(keys) == 0 {
		return false
	}
	cur := any(m)
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
	norm := strings.ToUpper(strings.TrimSpace(name))
	norm = strings.ReplaceAll(norm, "-", "_")
	norm = strings.ReplaceAll(norm, ".", "_")
	norm = strings.ReplaceAll(norm, " ", "_")
	parts := strings.Split(norm, "_")
	parts = slicesDeleteEmpty(parts)
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
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, " ", "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if s == "" {
		return "snapshot"
	}
	return s
}

func slicesDeleteEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}
