package initcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/initcmd/contextcmd"
	initenv "github.com/sufield/stave/cmd/initcmd/env"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/version"
)

// ---------------------------------------------------------------------------
// Bridge declarations: type aliases and delegating functions so the rest of
// this file can keep using the original (unexported) names while the canonical
// definitions live in cmdutil.
// ---------------------------------------------------------------------------

type RetentionTiersMap = cmdutil.RetentionTiersMap
type TierMappingRule = cmdutil.TierMappingRule

// Constant aliases.
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
	root.AddCommand(InitCmd)
	root.AddCommand(QuickstartCmd)
	root.AddCommand(DemoCmd)
	root.AddCommand(GenerateCmd)
	root.AddCommand(initconfig.NewConfigCmd(ui.NewRuntime(nil, nil)))
	root.AddCommand(contextcmd.ContextCmd)
	root.AddCommand(initenv.EnvCmd)
	root.AddCommand(initalias.AliasCmd)
	return root
}

// GetVersion returns the CLI version string.
func GetVersion() string { return version.Version }

// resolveNow parses a --now flag value. Returns wall clock UTC when raw is empty.
func resolveNow(raw string) (time.Time, error) {
	return cmdutil.ResolveNow(raw)
}

// snapshotObservationRepository combines ObservationRepository with single-reader loading.
type snapshotObservationRepository interface {
	appcontracts.ObservationRepository
	LoadSnapshotFromReader(ctx context.Context, r io.Reader, sourceName string) (asset.Snapshot, error)
}

func newSnapshotObservationRepository() (snapshotObservationRepository, error) {
	repo, err := cmdutil.NewSnapshotObservationRepository()
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// evalOutput returns os.Stdout or io.Discard based on quiet mode.
func evalOutput() io.Writer {
	if globalQuiet {
		return io.Discard
	}
	return os.Stdout
}

// Delegating functions — forward to cmdutil equivalents.

func resolveTierForPath(relPath string, rules []TierMappingRule, defaultTier string) string {
	return cmdutil.ResolveTierForPath(relPath, rules, defaultTier)
}
func matchGlobPattern(pattern, relPath string) (bool, error) {
	return cmdutil.MatchGlobPattern(pattern, relPath)
}

// ---------------------------------------------------------------------------
// End bridge declarations
// ---------------------------------------------------------------------------

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
