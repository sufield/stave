package logging

import (
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/sufield/stave/internal/sanitize"
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

	if c.isSensitiveLogKey(groups, a.Key) {
		return slog.String(a.Key, sanitize.SanitizedValue)
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

// infraKeys are log attribute keys that carry infrastructure identifiers.
// These are scrubbed only when SanitizeInfraKeys is enabled (--sanitize).
//
// `"error"` is intentionally absent: an error attribute often carries
// the only diagnostic information an operator has after a failed run.
// Scrubbing it under --sanitize made post-incident triage impossible
// because every log line wrapped in `"error": err` came back as
// "[SANITIZED]". If a specific error message embeds a sensitive
// identifier, the right answer is to redact at the formatting site
// (or rely on isSensitiveKey for the fields the error wraps), not to
// blanket-redact every error attribute.
var infraKeys = map[string]struct{}{
	"asset":   {},
	"control": {},
	"bucket":  {},
	"arn":     {},
	"account": {},
}

func (c Config) isSensitiveLogKey(groups []string, key string) bool {
	if key == "" {
		return false
	}
	if isSensitiveKey(key) {
		return true
	}
	if c.SanitizeInfraKeys {
		if _, ok := infraKeys[key]; ok {
			return true
		}
	}
	return slices.ContainsFunc(groups, isSensitiveKey)
}
