// Package logging provides structured logging for stave CLI.
//
// Design principles:
// - stdout is for command results only
// - stderr is for diagnostics (logs)
// - deterministic by default (no timestamps unless opted in)
// - privacy-safe (sanitization of sensitive fields)
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
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
}

// suppressTimestamps reports whether timestamps should be stripped for deterministic output.
func (c Config) suppressTimestamps() bool { return !c.Timestamps }

// sanitizeSourcePaths reports whether source file paths should be reduced to basenames for privacy.
func (c Config) sanitizeSourcePaths() bool { return !c.FullPaths }

func init() {
	// Set a resilient default before Setup is called: warn-level, text, stderr.
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

// LevelFromVerbosity returns the log level based on -v count.
func LevelFromVerbosity(v int) Level {
	switch {
	case v >= 2:
		return LevelDebug
	case v == 1:
		return LevelInfo
	default:
		return LevelWarn
	}
}

// ParseLevel parses a string into a Level.
func ParseLevel(s string) Level {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.TrimSpace(s))); err == nil {
		return level
	}
	return LevelWarn
}

// ParseFormat parses a string into a Format.
func ParseFormat(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON
	default:
		return FormatText
	}
}

// SetDefaultLogger updates the global slog default logger.
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

// LogCloser wraps a logger with an optional closer for file handles.
type LogCloser struct {
	Logger *slog.Logger
	closer io.Closer
}

// Close closes the underlying writer.
func (lc *LogCloser) Close() error {
	return lc.closer.Close()
}

// NewLogger creates a new logger based on configuration.
// Returns a LogCloser that should be closed when done.
func NewLogger(cfg Config) (*LogCloser, error) {
	wc, err := openLogWriter(cfg)
	if err != nil {
		return nil, err
	}

	logger := slog.New(newHandler(cfg, wc))

	return &LogCloser{
		Logger: logger,
		closer: wc,
	}, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func openLogWriter(cfg Config) (io.WriteCloser, error) {
	if cfg.LogFile == "" {
		return nopCloser{os.Stderr}, nil
	}
	return fsutil.SafeOpenAppend(cfg.LogFile, fsutil.WriteOptions{
		Perm:         0o644,
		AllowSymlink: cfg.AllowSymlink,
	})
}

func newHandler(cfg Config, out io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{
		Level:       cfg.Level,
		ReplaceAttr: cfg.Scrub,
	}

	if cfg.Format == FormatJSON {
		return slog.NewJSONHandler(out, opts)
	}
	return slog.NewTextHandler(out, opts)
}
