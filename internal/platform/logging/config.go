// Package logging provides structured logging for stave CLI.
//
// Design principles:
// - stdout is for command results only
// - stderr is for diagnostics (logs)
// - deterministic by default (no timestamps unless opted in)
// - privacy-safe (sanitization of sensitive fields)
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Format specifies log output format.
type Format string

// FormatText and related constants.
const (
	// FormatText constants.
	FormatText Format = "text"
	FormatJSON Format = "json"
	RunIDKey   string = "run_id"
)

// String / Set / Type satisfy pflag.Value so a Format-typed CLI flag
// field can bind via cobra's Flags().Var(&cfg.Format, "log-format", ...).
func (f Format) String() string      { return string(f) }
func (f *Format) Set(v string) error { *f = Format(v); return nil }
func (f Format) Type() string        { return "string" }

// LevelFlag is the string the user types on the --log-level CLI flag.
// Stored typed so the flag value flows through the program with its
// meaning intact; the eventual slog.Level conversion happens in
// ParseLevel.
type LevelFlag string

// String / Set / Type satisfy pflag.Value.
func (l LevelFlag) String() string      { return string(l) }
func (l *LevelFlag) Set(v string) error { *l = LevelFlag(v); return nil }
func (l LevelFlag) Type() string        { return "string" }

// LevelDebug and related constants.
const (
	// LevelDebug constants.
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Config holds logging configuration.
type Config struct {
	// Format is the output format (text or json).
	Format Format

	// Level is the minimum log level.
	Level slog.Level

	// LogFile is an optional file path for log output.
	// If empty, logs go to stderr.
	LogFile string

	// AllowSymlink permits writing through symlinks (default: refuse).
	AllowSymlink bool

	// Timestamps enables RFC3339 timestamps in logs.
	// Disabled by default for determinism.
	Timestamps bool

	// Timings enables duration logging for major steps.
	// Disabled by default for determinism.
	Timings bool

	// FullPaths logs full file paths instead of base names.
	// Disabled by default for privacy.
	FullPaths bool

	// SanitizeInfraKeys scrubs infrastructure identifier values (asset,
	// control, bucket, arn, account) from log attributes. Enabled when
	// the --sanitize CLI flag is active.
	SanitizeInfraKeys bool
}

// suppressTimestamps reports whether timestamps should be stripped for deterministic output.
func (c Config) suppressTimestamps() bool { return !c.Timestamps }

// sanitizeSourcePaths reports whether source file paths should be reduced to basenames for privacy.
func (c Config) sanitizeSourcePaths() bool { return !c.FullPaths }

// InitDefaultLogger sets a warn-level text handler on stderr as the
// process-wide slog default. Call this once from the application
// constructor (e.g. NewApp) rather than relying on init().
func InitDefaultLogger() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: LevelWarn,
	})))
}

// DefaultConfig returns the default logging configuration.
func DefaultConfig() Config {
	return Config{
		Format:     FormatText,
		Level:      LevelWarn,
		LogFile:    "",
		Timestamps: false,
		Timings:    false,
		FullPaths:  false,
	}
}

// SetDefaultLogger updates the global slog default logger.
// This should only be called from the bootstrap phase (cmd/bootstrap.go).
// Application-layer code should receive a logger via injection (struct field
// or context) rather than reading slog.Default().
func SetDefaultLogger(logger *slog.Logger) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: LevelWarn,
		}))
	}
	slog.SetDefault(logger)
}

// DefaultLogger returns the global slog default logger.
func DefaultLogger() *slog.Logger {
	return slog.Default()
}

// WithRunID returns the logger enriched with run_id, or the logger
// unchanged when runID is blank.
func WithRunID(logger *slog.Logger, runID string) *slog.Logger {
	id := strings.TrimSpace(runID)
	if id == "" {
		return logger
	}
	return logger.With(slog.String(RunIDKey, id))
}
