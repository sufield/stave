package logging

import (
	"strings"

	"github.com/sufield/stave/internal/sanitize"
)

func toLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

// isSensitiveKey reports whether a flag name indicates its value is sensitive.
// Sensitive names and tokens are defined centrally in the scrub package.
func isSensitiveKey(key string) bool {
	if key == "" {
		return false
	}

	// Normalize once: lowercase, strip CLI dashes, strip =value suffix.
	norm := toLower(key)
	norm = strings.TrimLeft(norm, "-")
	norm, _, _ = strings.Cut(norm, "=")
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
