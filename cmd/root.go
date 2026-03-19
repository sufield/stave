package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/configservice"
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
	CPUProfile      string // write CPU profile to file
	MemProfile      string // write heap profile to file
}

// AppOption configures optional behaviour on an App before it is returned
// from NewApp. Use WithDevCommands to build the full developer binary.
type AppOption func(*App)

// WithDevCommands returns an AppOption that registers all developer-only
// commands and sets the binary edition to "dev".
func WithDevCommands() AppOption {
	return func(app *App) {
		app.Edition = EditionDev
		WireDevCommands(app)
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
	cpuProfileFile *os.File // held open during execution, closed in postRun

	// Provider holds the adapter constructor wiring used by command handlers.
	// It is initialised from compose.NewDefaultProvider() and threaded through
	// command constructors at registration time. Replace it before calling
	// NewApp to swap adapters in tests or custom entry points.
	Provider *compose.Provider

	// ConfigKeyService is the config-key resolution service used by the
	// "stave config" command tree. It is passed explicitly to NewConfigCmd so
	// the config handlers do not depend on the projconfig package-level global.
	ConfigKeyService *configservice.Service

	// sanitizer is initialized from CLI flags during bootstrap and used for
	// path/message sanitization in error handling and panic recovery.
	sanitizer *sanitize.Sanitizer
}

// NewApp creates a fully-wired CLI application.
// Pass WithDevCommands() to build the stave-dev binary with all commands.
func NewApp(opts ...AppOption) *App {
	logging.InitDefaultLogger()
	app := &App{
		Edition:          EditionProd,
		ExitFunc:         os.Exit,
		Provider:         compose.NewDefaultProvider(),
		ConfigKeyService: projconfig.ConfigKeyService,
	}
	app.Root = &cobra.Command{
		Use:               CLIName,
		Short:             "Configuration safety evaluator",
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: app.bootstrap,
		PersistentPostRun: app.postRun,
		Long:              rootLongHelp,
	}
	AddGlobalFlags(app.Root, &app.Flags)
	WireProdCommands(app)

	for _, opt := range opts {
		opt(app)
	}

	app.Root.Version = fmt.Sprintf("%s (%s)", GetVersion(), string(app.Edition))
	wireProdHelpGroups(app.Root)
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

func (a *App) isJSONMode() bool {
	return a.Flags.OutputMode == string(ui.OutputFormatJSON)
}

func (a *App) initSanitizer() {
	a.sanitizer = sanitize.Policy{
		SanitizeIDs: a.Flags.Sanitize,
		PathMode:    cmdutil.ParsePathMode(a.Flags.PathMode),
	}.NewSanitizer()
}

// GetVersion returns the version string.
func GetVersion() string {
	return staveversion.Version
}

// GetRootCmd returns a fully-wired root cobra command for tests and doc generation.
func GetRootCmd() *cobra.Command {
	return NewApp().Root
}
