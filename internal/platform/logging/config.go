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

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	RunIDKey   string = "run_id"
)

// Level maps directly to slog levels.
type Level = slog.Level

const (
	LevelDebug Level = slog.LevelDebug
	LevelInfo  Level = slog.LevelInfo
	LevelWarn  Level = slog.LevelWarn
	LevelError Level = slog.LevelError
)

// Config holds logging configuration.
type Config struct {
	// Format is the output format (text or json).
	Format Format

	// Level is the minimum log level.
	Level Level

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
