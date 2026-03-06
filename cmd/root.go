package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/sanitize"
	staveversion "github.com/sufield/stave/internal/version"
)

// globalFlagsType groups all persistent CLI flags into a single struct,
// following the same pattern as applyFlagsType in cmd/evaluate/command.go.
type globalFlagsType struct {
	OutputMode      string // "json" or "text"
	Quiet           bool   // suppress non-essential output
	Verbosity       int    // -v count (0=WARN, 1=INFO, 2+=DEBUG)
	LogLevel        string // explicit log level override
	LogFormat       string // "text" or "json"
	LogFile         string // optional log file path
	LogTimestamps   bool   // enable timestamps (breaks determinism)
	LogTimings      bool   // enable timing logs (breaks determinism)
	Sanitize        bool   // sanitize infrastructure identifiers from output
	PathMode        string // "base" (default) or "full" — controls path rendering
	Force           bool   // allow overwriting existing output files
	AllowSymlinkOut bool   // allow writing through symlinks
	RequireOffline  bool   // runtime self-check for offline operation
	Strict          bool   // enable strict runtime integrity checks
	NoColor         bool   // disable colored output even on TTY
}

// gFlags holds all persistent CLI flag values.
var gFlags globalFlagsType

// globalLogger is the structured logger for all commands.
var globalLogger *slog.Logger

// globalLogCloser holds the log file closer if applicable.
var globalLogCloser *logging.LogCloser

// exitFunc is used for terminating the process. It is a variable to allow tests
// to override process exit behavior without affecting production code paths.
var exitFunc = os.Exit

// CLI metadata is re-exported from internal/metadata to keep command code concise
// while centralizing ownership outside cmd/.
const (
	CLIName           = metadata.CLIName
	OfflineHelpSuffix = metadata.OfflineHelpSuffix
	CLIIssuesURL      = metadata.CLIIssuesURL
	CLIProjectConfig  = metadata.CLIProjectConfig
	CLILockfile       = metadata.CLILockfile
)

func cliCommand(command string) string {
	return metadata.Command(command)
}

// Sentinel errors re-exported from cli/ui for convenience.
// These trigger specific exit codes via ExitCode().
var (
	ErrViolationsFound       = ui.ErrViolationsFound
	ErrDiagnosticsFound      = ui.ErrDiagnosticsFound
	ErrValidationWarnings    = ui.ErrValidationWarnings
	ErrValidationFailed      = ui.ErrValidationFailed
	ErrSecurityAuditFindings = ui.ErrSecurityAuditFindings
)

// ExitCode delegates to ui.ExitCode for centralized exit code logic.
func ExitCode(err error) int {
	return ui.ExitCode(err)
}

// IsJSONMode returns true if global output mode is JSON.
func IsJSONMode() bool {
	return gFlags.OutputMode == "json"
}

// GetSanitizationPolicy returns the unified OutputSanitizationPolicy derived from CLI flags.
func GetSanitizationPolicy() sanitize.OutputSanitizationPolicy {
	pathMode := sanitize.ParsePathMode(gFlags.PathMode)
	return sanitize.OutputSanitizationPolicy{
		SanitizeIDs: gFlags.Sanitize,
		PathMode:    pathMode,
	}
}

// resolvePathSanitize returns true when error paths should be shortened.
func resolvePathSanitize() bool {
	return GetSanitizationPolicy().ShouldSanitizePaths()
}

// GetVersion returns the version string.
func GetVersion() string {
	return staveversion.Version
}

// GetRootCmd returns the root cobra command for documentation generation.
func GetRootCmd() *cobra.Command {
	return RootCmd
}

// NewRootCmd builds the CLI root command.
func NewRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:               CLIName,
		Short:             "Configuration safety evaluator",
		Version:           GetVersion(),
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: bootstrapRootCommand,
		PersistentPostRun: postRunRootCommand,
		Long:              rootLongHelp,
	}
}

// RootCmd represents the base command when called without any subcommands.
var RootCmd = NewRootCmd()
