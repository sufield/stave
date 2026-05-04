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

	// Explicit state machine: skipNext captures the
	// "currently-consuming-the-value-of-a-sensitive-flag" state so
	// the next iteration cannot misidentify that already-consumed
	// value as a fresh flag. The earlier `i++` mid-loop trick
	// composed with the outer `i++` to land at the right index by
	// arithmetic accident — easy to break under future edits.
	skipNext := false
	for i, arg := range args {
		if skipNext {
			// args[i] is the value of a previous sensitive flag.
			// Already redacted in result[i]; reset and move on.
			skipNext = false
			continue
		}

		if name, _, hasEq := strings.Cut(arg, "="); hasEq {
			if isSensitiveKey(name) {
				result[i] = name + "=" + sanitize.SanitizedValue
			}
			continue
		}

		if !isSensitiveKey(arg) {
			continue
		}

		if i+1 >= len(args) {
			// Sensitive flag is the trailing arg. The value is
			// missing structurally, but we still want the log
			// line to communicate that a value was expected so
			// the operator can correlate against shell history.
			result[i] = arg + " " + sanitizedValueMissing
			continue
		}
		// If the next arg is itself a known sensitive flag,
		// don't consume it — let the next loop iteration
		// redact it independently. The previous shape consumed
		// blindly, so `--token --password mysecret` redacted
		// only `--password` (treated as --token's value) and
		// left `mysecret` exposed in position 2.
		//
		// The look-ahead requires the next arg to start with
		// `--` so a *value* that happens to contain a
		// sensitive token (e.g. `-very-secret-pass`) is not
		// mistaken for a flag.
		if strings.HasPrefix(args[i+1], "--") && isSensitiveKey(args[i+1]) {
			result[i] = arg + " " + sanitizedValueMissing
			continue
		}
		// Otherwise: always redact. A legitimate password /
		// token / api-key value can start with `-`; over-
		// redacting an actual flag is cheaper than under-
		// redacting a credential.
		result[i+1] = sanitize.SanitizedValue
		skipNext = true
	}

	return result
}
