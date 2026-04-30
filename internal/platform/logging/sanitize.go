package logging

import (
	"strings"

	"github.com/sufield/stave/internal/sanitize"
)

// isSensitiveKey reports whether a flag name indicates its value is sensitive.
// Sensitive names and tokens are defined centrally in the scrub package.
func isSensitiveKey(key string) bool {
	if key == "" {
		return false
	}

	// Normalize once: lowercase, strip CLI dashes, strip =value suffix.
	norm := strings.ToLower(key)
	norm = strings.TrimLeft(norm, "-")
	if i := strings.IndexByte(norm, '='); i >= 0 {
		norm = norm[:i]
	}
	if norm == "" {
		return false
	}

	// Exact match against known sensitive flag names.
	if _, ok := sanitize.SensitiveArgNames[norm]; ok {
		return true
	}

	// Token match: split on separators, check each segment.
	tokens := strings.FieldsFunc(norm, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ':'
	})
	for _, t := range tokens {
		if _, ok := sanitize.SensitiveTokens[t]; ok {
			return true
		}
	}

	return false
}

// SanitizeArgs sanitizes sensitive values from command arguments.
// It handles both --key=value and --key value patterns.
//
// The redaction is conservative — when a sensitive flag is the last
// argument or its value happens to start with `-` (a legitimate use
// case for some passwords / tokens), the value is still redacted
// rather than passed through, because the cost of over-redacting an
// arg is far less than the cost of leaking a credential into shell
// history or telemetry. Empty placeholder for a missing trailing
// value documents the structural problem so the caller (typically a
// log line) reads correctly: `--password [SANITIZED:missing]`.
const sanitizedValueMissing = sanitize.SanitizedValue + ":missing"

func SanitizeArgs(args []string) []string {
	result := append([]string(nil), args...)

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if name, _, hasEq := strings.Cut(arg, "="); hasEq {
			if isSensitiveKey(name) {
				result[i] = name + "=" + sanitize.SanitizedValue
			}
			continue
		}

		if isSensitiveKey(arg) {
			if i+1 >= len(args) {
				// Sensitive flag is the trailing arg. The value is
				// missing structurally, but we still want the log
				// line to communicate that a value was expected so
				// the operator can correlate against shell history.
				result[i] = arg + " " + sanitizedValueMissing
				continue
			}
			// Sensitive value: always redact. The previous shape
			// skipped redaction when the value `looks like a flag`
			// (starts with `-`), but a legitimate
			// password / token / api-key starting with `-` is a
			// real input pattern — over-redacting an actual flag
			// is far cheaper than under-redacting a credential.
			result[i+1] = sanitize.SanitizedValue
			i++
		}
	}

	return result
}
