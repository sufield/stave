package logging

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/sufield/stave/internal/pkg/sensitive"
)

// SanitizedValue is the placeholder for sensitive values.
const SanitizedValue = "[SANITIZED]"

// sensitiveSubstrings caches the shared substring set at init time.
var sensitiveSubstrings = sensitive.SubstringKeywords()

// isSensitiveKey reports whether a key name suggests sensitive data.
// Uses a tiered approach: exact match -> token match -> substring match.
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

	// Fast: exact match against precomputed map.
	if sensitive.IsExactKey(norm) {
		return true
	}

	// Medium: tokenize on separators, check each token.
	if strings.ContainsAny(norm, "_-.:") {
		tokens := strings.FieldsFunc(norm, func(r rune) bool {
			return r == '_' || r == '-' || r == '.' || r == ':'
		})
		if slices.ContainsFunc(tokens, sensitive.IsExactKey) {
			return true
		}
	}

	// Slow: substring match for compound names (e.g. "accesstoken").
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(norm, sub) {
			return true
		}
	}

	return false
}

// SanitizePath returns the base name of a path unless fullPaths is true.
func SanitizePath(path string, fullPaths bool) string {
	if fullPaths || path == "" {
		return path
	}
	return filepath.Base(path)
}

// truncateString truncates a string to maxLen runes, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	// Fast exit: if byte length fits, rune count fits too.
	if len(s) <= maxLen {
		return s
	}
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

// SanitizeArgs sanitizes sensitive values from command arguments.
// It handles both --key=value and --key value patterns.
func SanitizeArgs(args []string) []string {
	result := append([]string(nil), args...)

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if name, _, hasEq := strings.Cut(arg, "="); hasEq {
			if isSensitiveKey(name) {
				result[i] = name + "=" + SanitizedValue
			}
			continue
		}

		if isSensitiveKey(arg) {
			if i+1 < len(args) && !isLikelyFlagToken(args[i+1]) {
				result[i+1] = SanitizedValue
				i++
			}
		}
	}

	return result
}

func isLikelyFlagToken(arg string) bool {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" || trimmed == "-" {
		return false
	}
	if strings.HasPrefix(trimmed, "--") {
		return len(trimmed) > 2
	}
	if strings.HasPrefix(trimmed, "-") && len(trimmed) > 1 {
		ch := trimmed[1]
		return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
	}
	return false
}
