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

// ParseLevel parses a string into a Level. Falls back to LevelWarn on
// any parse error, with a slog warning so a typo in --log-level or
// STAVE_LOG_LEVEL doesn't silently downgrade to warn-mode without the
// operator noticing. Empty input is the documented "use default" path
// and skips the warn so it stays log-noise free.
func ParseLevel(s string) slog.Level {
	var level slog.Level
	trimmed := strings.TrimSpace(s)
	if err := level.UnmarshalText([]byte(trimmed)); err == nil {
		return level
	}
	if trimmed != "" {
		slog.Warn("logging.ParseLevel: invalid log level; falling back to default",
			"input", trimmed, "fallback", LevelWarn.String())
	}
	return LevelWarn
}

// ParseFormat parses a string into a Format.
func ParseFormat(s string) Format {
	if s == "json" {
		return FormatJSON
	}
	if s == "text" || s == "" {
		return FormatText
	}
	trimmed := strings.TrimSpace(s)
	if strings.EqualFold(trimmed, "json") {
		return FormatJSON
	}
	return FormatText
}
