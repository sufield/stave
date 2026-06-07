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
	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/internal/platform/providers/aws"

	// Blank import: each control's init() registers into the global
	// compliance.ControlCatalog. Importing the AWS provider package
	// itself does not transitively load this — the AWS package
	// stays leaf-imported so providers/aws/compliance can depend on
	// providers/aws without creating a cycle.
	_ "github.com/sufield/stave/internal/platform/providers/aws/compliance"
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

// SetPathMode validates v before assigning. Allowed values are "base"
// (basename only in error messages) and "full" (absolute paths).
// Returns an error so a typo'd project_config (`path_mode: bsae`)
// surfaces at config-resolution time instead of silently accepting
// the malformed value and downstream code applying a non-existent
// rendering mode.
func (g *globalFlagsType) SetPathMode(v string) error {
	switch v {
	case "base", "full":
		g.PathMode = cliflags.PathModeFlag(v)
		return nil
	}
	return fmt.Errorf("invalid path-mode %q (allowed: \"base\", \"full\")", v)
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
	Quiet           bool                  // suppress non-essential output
	Yes             bool                  // auto-confirm all interactive prompts
	Verbosity       int                   // -v count (0=WARN, 1=INFO, 2+=DEBUG)
	LogLevel        logging.LevelFlag     // explicit log level override
	LogFormat       logging.Format        // "text" or "json"
	LogFile         string                // optional log file path
	LogTimestamps   bool                  // enable timestamps (breaks determinism)
	LogTimings      bool                  // enable timing logs (breaks determinism)
	Sanitize        bool                  // sanitize infrastructure identifiers from output
	PathMode        cliflags.PathModeFlag // "base" (default) or "full" — controls path rendering; validated at parse time
	Force           bool                  // allow overwriting existing output files
	AllowSymlinkOut bool                  // allow writing through symlinks
	RequireOffline  bool                  // runtime self-check for offline operation
	Strict          bool                  // enable strict runtime integrity checks
	NoColor         bool                  // disable colored output even on TTY
	CPUProfile      string                // write CPU profile to file
	MemProfile      string                // write heap profile to file
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
	// memProfileWritten gates writeMemProfileTo so the profile is
	// emitted exactly once across the (finalize / cleanupBeforeExit /
	// recoverExecutePanic) call sites. Without it, a panic mid-run
	// caused two writes (one from the recover path, one from the
	// deferred finalize) and the second open-with-O_TRUNC clobbered
	// the first.
	memProfileWritten atomic.Bool
	// cancel is published by bootstrap (phaseContext) and read by the
	// signal-handler goroutine. atomic.Pointer makes the publish/load
	// race-free without locking the read path. cleanupBeforeExit uses
	// Swap(nil) (not Load) so a peer cleanup goroutine that races us
	// gets nil and skips the cancel — context.CancelFunc is itself
	// idempotent, but Swap also publishes the "already cancelled"
	// state so subsequent goroutines do not need to take the call.
	cancel atomic.Pointer[context.CancelFunc]

	// cleanupOnce gates cleanupBeforeExit. The function is invoked
	// from four call sites that may race (handleExecutionError,
	// recoverExecutePanic, signal handler, ctx-deadline finalizer);
	// each underlying step is individually idempotent, but folding
	// the whole path through sync.Once makes the contract explicit
	// and avoids re-running the bootstrap-mutex dance + log-close
	// retry on every concurrent cleanup attempt.
	cleanupOnce sync.Once

	// logCloseOnce serialises LogCloser.Close + the
	// "Warning: close log file" stderr write across the two paths
	// that can both reach it: postRun (normal exit) and
	// cleanupBeforeExit (panic / signal / ctx-deadline finalizer).
	// LogCloser.Close itself is internally sync.Once-guarded, but the
	// stderr-warning emission was duplicated at each call site, so a
	// failed close on the normal path could surface twice (postRun
	// fires, then cleanupBeforeExit runs and re-reads the stored
	// error). One sync.Once collapses both the close and the warning
	// into a single observable event regardless of which path won.
	logCloseOnce sync.Once

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
	// confidenceInitialized is the explicit "we have a useful
	// Confidence value" flag. Bootstrap sets it true after seeding
	// the defaults; tests / harnesses that pre-populate Confidence
	// before calling phaseConfig should set it true themselves so
	// their values are not silently overwritten by the default
	// seed. The earlier shape compared a.Confidence to the zero
	// value, which conflated "uninitialised" with "explicitly all
	// multipliers = 0" — a legitimate-but-rare configuration that
	// would be silently replaced by the default.
	confidenceInitialized bool

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
	// Register the AWS provider into the kernel registries before any
	// command runs. Idempotent and concurrent-safe; explicit so the
	// dependency on AWS is visible at the CLI's wiring boundary
	// instead of hidden behind blank-import side effects.
	aws.Register()
	// Wire the embedded policy library so app/capabilities.Manifest
	// has its data source. Idempotent.
	capabilities.Configure(pack.MustNewLibrary())
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
		// Cobra invokes the deepest matching PersistentPostRun in the
		// command tree — a subcommand that defines its own
		// PersistentPostRun would silently REPLACE this hook, skipping
		// app.postRun's CPU-profile stop, mem-profile write, and log
		// flush. Today no subcommand under cmd/ defines a Persistent
		// hook (audited via `grep PersistentPostRun cmd/`); future
		// additions must wrap, not override, this hook.
		PersistentPostRun: app.postRun,
		Long:              rootLongHelp,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
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
	// Man-page-style, paged --help across the tree (installed after groups so the
	// group-aware template renders them) + a hidden gen-man that emits real *.1
	// pages.
	ApplyManStyle(app.Root)
	app.Root.AddCommand(NewGenManCmd(app.Root, Version()))
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
