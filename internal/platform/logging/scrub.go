package logging

import (
	"log/slog"
	"path/filepath"
	"slices"
)

// Scrub transforms a slog.Attr based on the config's logging policy:
// suppress timestamps for determinism, sanitize source paths for privacy,
// and sanitize sensitive keys.
func (c Config) Scrub(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		if c.suppressTimestamps() {
			return slog.Attr{}
		}
	case slog.SourceKey:
		if c.sanitizeSourcePaths() {
			return c.sanitizeSource(a)
		}
	}

	if isSensitiveLogKey(groups, a.Key) {
		return slog.String(a.Key, SanitizedValue)
	}

	return a
}

func (c Config) sanitizeSource(a slog.Attr) slog.Attr {
	src, ok := a.Value.Any().(*slog.Source)
	if !ok || src == nil {
		return a
	}
	cp := *src
	cp.File = filepath.Base(cp.File)
	return slog.Any(a.Key, &cp)
}

func isSensitiveLogKey(groups []string, key string) bool {
	if key == "" {
		return false
	}
	if isSensitiveKey(key) {
		return true
	}
	return slices.ContainsFunc(groups, isSensitiveKey)
}
