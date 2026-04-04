package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/sanitize"
	staveversion "github.com/sufield/stave/internal/version"
)

// globalFlagsType groups all persistent CLI flags into a single struct,
// following the same pattern as applyFlagsType in cmd/apply/command.go.
type globalFlagsType struct {
	Quiet           bool   // suppress non-essential output
	Yes             bool   // auto-confirm all interactive prompts
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
	CPUProfile      string // write CPU profile to file
	MemProfile      string // write heap profile to file
}

// AppOption configures optional behaviour on an App before it is returned
// from NewApp. Use WithDevEdition to build the full developer binary.
type AppOption func(*App)

// WithDevEdition returns an AppOption that sets the binary edition to "dev".
// All commands are registered in WireCommands regardless of edition.
func WithDevEdition() AppOption {
	return func(app *App) {
		app.Edition = EditionDev
	}
}

// App owns all CLI-wide mutable state, eliminating package-level globals
// and making the CLI reentrant.
type App struct {
	// Edition identifies the binary variant (EditionProd or EditionDev).
	// It is embedded in --version output so bug reports identify which
	// binary is running.
	Edition Edition

	Flags          globalFlagsType
	Logger         *slog.Logger
	LogCloser      *logging.LogCloser
	ExitFunc       func(int)
	Root           *cobra.Command
	cpuProfileFile *os.File           // held open during execution, closed in postRun
	cancel         context.CancelFunc // set by bootstrap, called by signal handler

	// Provider holds the adapter constructor wiring used by command handlers.
	// It is initialised from compose.NewDefaultProvider() and threaded through
	// command constructors at registration time. Replace it before calling
	// NewApp to swap adapters in tests or custom entry points.
	Provider *compose.Provider

	// Confidence holds the configurable confidence thresholds, set during
	// bootstrap from stave.yaml. Passed to the engine Runner.
	Confidence evaluation.ConfidenceCalculator

	// sanitizer is initialized from CLI flags during bootstrap and used for
	// path/message sanitization in error handling and panic recovery.
	sanitizer *sanitize.Sanitizer
}

// NewApp creates a fully-wired CLI application.
// Pass WithDevEdition() to build the stave-dev binary with all commands.
func NewApp(opts ...AppOption) *App {
	logging.InitDefaultLogger()
	app := &App{
		Edition:  EditionProd,
		ExitFunc: os.Exit,
		Provider: compose.NewDefaultProvider(),
	}
	app.Root = &cobra.Command{
		Use:                CLIName,
		Short:              "Configuration safety evaluator",
		SilenceErrors:      true,
		SilenceUsage:       true,
		DisableSuggestions: true,
		PersistentPreRunE:  app.bootstrap,
		PersistentPostRun:  app.postRun,
		Long:               rootLongHelp,
		CompletionOptions:  cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	AddGlobalFlags(app.Root, &app.Flags)
	WireCommands(app)

	for _, opt := range opts {
		opt(app)
	}

	app.Root.Version = fmt.Sprintf("%s (%s)", Version(), string(app.Edition))
	wireHelpGroups(app.Root)
	return app
}

// CLI metadata is re-exported from internal/metadata to keep command code concise
// while centralizing ownership outside cmd/.
const (
	CLIName           = metadata.CLIName
	OfflineHelpSuffix = metadata.OfflineHelpSuffix
	CLIProjectConfig  = metadata.CLIProjectConfig
	CLILockfile       = metadata.CLILockfile
)

func cliCommand(command string) string {
	return metadata.Command(command)
}

// ExitCode delegates to ui.ExitCode for centralized exit code logic.
func ExitCode(err error) int {
	return ui.ExitCode(err)
}

func (a *App) initSanitizer() {
	a.sanitizer = sanitize.Policy{
		SanitizeIDs: a.Flags.Sanitize,
		PathMode:    cliflags.ParsePathMode(a.Flags.PathMode),
	}.NewSanitizer()
}

// Version returns the version string.
func Version() string {
	return staveversion.String
}
