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
// following the same pattern as applyFlagsType in cmd/apply/command.go.
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

// App owns all CLI-wide mutable state, eliminating package-level globals
// and making the CLI reentrant.
type App struct {
	Flags     globalFlagsType
	Logger    *slog.Logger
	LogCloser *logging.LogCloser
	ExitFunc  func(int)
	Root      *cobra.Command
}

// NewApp creates a fully-wired CLI application.
func NewApp() *App {
	app := &App{ExitFunc: os.Exit}
	app.Root = &cobra.Command{
		Use:               CLIName,
		Short:             "Configuration safety evaluator",
		Version:           GetVersion(),
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: app.bootstrap,
		PersistentPostRun: app.postRun,
		Long:              rootLongHelp,
	}
	AddGlobalFlags(app.Root, &app.Flags)
	WireMetaCommands(app.Root)
	WireCommands(app.Root)
	wireHelpGroups(app.Root)
	return app
}

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

func (a *App) isJSONMode() bool {
	return a.Flags.OutputMode == "json"
}

func (a *App) getSanitizationPolicy() sanitize.OutputSanitizationPolicy {
	pathMode := sanitize.ParsePathMode(a.Flags.PathMode)
	return sanitize.OutputSanitizationPolicy{
		SanitizeIDs: a.Flags.Sanitize,
		PathMode:    pathMode,
	}
}

func (a *App) resolvePathSanitize() bool {
	return a.getSanitizationPolicy().ShouldSanitizePaths()
}

// GetVersion returns the version string.
func GetVersion() string {
	return staveversion.Version
}

// GetRootCmd returns a fully-wired root cobra command for tests and doc generation.
func GetRootCmd() *cobra.Command {
	return NewApp().Root
}
