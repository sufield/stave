package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/sanitize"
	staveversion "github.com/sufield/stave/internal/version"
)

// LoggingConfig builds a logging.Config from the global flags. The
// caller-side seven-field walk used to live in initLogger; pulling the
// transformation onto the type that owns the source fields means a
// new logging knob is one edit (struct field + this method) instead
// of an add-and-thread across every initLogger-like wiring point.
func (g *globalFlagsType) LoggingConfig() logging.Config {
	cfg := logging.DefaultConfig()
	if g.LogLevel != "" {
		cfg.Level = logging.ParseLevel(string(g.LogLevel))
	} else {
		cfg.Level = logging.LevelFromVerbosity(g.Verbosity)
	}
	cfg.Format = logging.ParseFormat(string(g.LogFormat))
	cfg.LogFile = fsutil.CleanUserPath(g.LogFile)
	cfg.Timestamps = g.LogTimestamps
	cfg.Timings = g.LogTimings
	cfg.AllowSymlink = g.AllowSymlinkOut
	cfg.SanitizeInfraKeys = g.Sanitize
	return cfg
}

// ProfilerConfig returns the cleaned CPU and memory pprof file paths.
// Empty strings mean "no profile requested for that profiler"; both
// callers (startCPUProfile, writeMemProfileTo) already short-circuit
// on the empty case so callers don't need to repeat the ""-check.
func (g *globalFlagsType) ProfilerConfig() (cpuPath, memPath string) {
	return fsutil.CleanUserPath(g.CPUProfile), fsutil.CleanUserPath(g.MemProfile)
}

// SetQuiet / SetSanitize / SetPathMode satisfy
// appconfig.FlagDefaultsTarget so the resolver can write
// project-config defaults onto these fields without importing
// globalFlagsType. PathMode round-trips through cliflags.PathModeFlag
// so the typed-value contract on the field is preserved.
func (g *globalFlagsType) SetQuiet(v bool)    { g.Quiet = v }
func (g *globalFlagsType) SetSanitize(v bool) { g.Sanitize = v }
func (g *globalFlagsType) SetPathMode(v string) {
	g.PathMode = cliflags.PathModeFlag(v)
}

// AllowsNetworkAccess reports whether the operator has NOT asserted
// the offline-only guarantee via --require-offline. Renames the
// inverse of the technical RequireOffline flag into a behaviour-
// oriented permission so callers in cmd/bootstrap stop reading
// !RequireOffline directly. Stave never makes network calls in
// normal operation; the flag exists to surface mis-configured proxy
// envs to operators who rely on the airgap guarantee.
func (g *globalFlagsType) AllowsNetworkAccess() bool {
	return g != nil && !g.RequireOffline
}

// globalFlagsType groups all persistent CLI flags into a single struct,
// following the same pattern as applyFlagsType in cmd/apply/command.go.
type globalFlagsType struct {
	Quiet           bool              // suppress non-essential output
	Yes             bool              // auto-confirm all interactive prompts
	Verbosity       int               // -v count (0=WARN, 1=INFO, 2+=DEBUG)
	LogLevel        logging.LevelFlag // explicit log level override
	LogFormat       logging.Format    // "text" or "json"
	LogFile         string            // optional log file path
	LogTimestamps   bool              // enable timestamps (breaks determinism)
	LogTimings      bool              // enable timing logs (breaks determinism)
	Sanitize        bool              // sanitize infrastructure identifiers from output
	PathMode        cliflags.PathModeFlag // "base" (default) or "full" — controls path rendering; validated at parse time
	Force           bool              // allow overwriting existing output files
	AllowSymlinkOut bool              // allow writing through symlinks
	RequireOffline  bool              // runtime self-check for offline operation
	Strict          bool              // enable strict runtime integrity checks
	NoColor         bool              // disable colored output even on TTY
	CPUProfile      string            // write CPU profile to file
	MemProfile      string            // write heap profile to file
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

	Flags     globalFlagsType
	Logger    *slog.Logger
	LogCloser *logging.LogCloser
	ExitFunc  func(int)
	Root      *cobra.Command
	// bootstrapMu serializes the bootstrap-time field writes
	// (Logger, LogCloser) against the pre-bootstrap signal
	// goroutine's reads in cleanupBeforeExit. Without this lock,
	// a SIGINT that lands while phaseLogging is mid-assignment
	// could race the goroutine reading a torn pointer. The mutex
	// covers only the bootstrap → cleanup boundary; mid-run reads
	// after bootstrap completes are safe because the values
	// don't change.
	bootstrapMu sync.Mutex
	// cpuProfileFile is the open profile file held while a CPU
	// profile is recording. Stored atomically so the bootstrap-
	// path startCPUProfile and the panic-recovery / signal-path
	// stopCPUProfile cannot race when both fire near the same
	// instant (mocked ExitFunc in tests, mid-execution panic).
	cpuProfileFile atomic.Pointer[os.File]
	// cancel is published by bootstrap (phaseContext) and read by the
	// signal-handler goroutine. atomic.Pointer makes the publish/load
	// race-free without locking the read path.
	cancel atomic.Pointer[context.CancelFunc]

	// cleanupInterrupt is the closure returned by installInterruptHandler
	// that stops signal delivery and unblocks the handler goroutine.
	// Stored on the App so the panic-recovery path can invoke it before
	// ExitFunc — otherwise a mocked ExitFunc (test) leaves the handler
	// goroutine blocked in its select forever.
	//
	// Held inside an atomic.Pointer because two goroutines can read or
	// reset the closure: Execute's deferred normal-path cleanup, and
	// recoverExecutePanic running on the panic stack. The earlier
	// plain-pointer field racy-read pattern was caught by `go test
	// -race` in tests that injected a panic mid-Execute.
	cleanupInterrupt atomic.Pointer[func()]

	// Confidence holds the configurable confidence thresholds, set during
	// bootstrap from stave.yaml. Passed to the engine Runner.
	Confidence evaluation.ConfidenceCalculator

	// sanitizer is initialized from CLI flags during bootstrap and used for
	// path/message sanitization in error handling and panic recovery.
	sanitizer *sanitize.Sanitizer

	// configResult holds the config resolution result between bootstrap phases.
	// Set in phaseConfig, consumed in phaseValidate and phaseLogging.
	configResult projconfig.ResolverResult
}

// NewApp creates a fully-wired CLI application.
// Pass WithDevEdition() to build the stave-dev binary with all commands.
// Returns an error if WireCommands fails — callers must propagate this
// (Execute / ExecuteDev exit with ExitInternal) so wiring failures show
// as a clean stderr message instead of a panic stack trace.
func NewApp(opts ...AppOption) (*App, error) {
	logging.InitDefaultLogger()
	app := &App{
		Edition:  EditionProd,
		ExitFunc: os.Exit,
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
	if err := WireCommands(app); err != nil {
		return nil, err
	}

	for _, opt := range opts {
		opt(app)
	}

	app.Root.Version = fmt.Sprintf("%s (%s)", Version(), string(app.Edition))
	wireHelpGroups(app.Root)
	return app, nil
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
		PathMode:    cliflags.ParsePathMode(string(a.Flags.PathMode)),
	}.NewSanitizer()
}

// Version returns the version string.
func Version() string {
	return staveversion.String
}
