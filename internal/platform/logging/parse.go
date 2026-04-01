package logging

import (
	"log/slog"
	"strings"
)

// LevelFromVerbosity returns the log level based on -v count.
func LevelFromVerbosity(v int) slog.Level {
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
func ParseLevel(s string) slog.Level {
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
