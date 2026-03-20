package logging

import (
	"strings"
)

// SanitizedValue is the placeholder for sensitive values.
const SanitizedValue = "[SANITIZED]"

// sensitiveArgNames are complete flag names (normalized, lowercase) known to
// carry sensitive values. Add entries here when stave gains flags that accept
// secrets, tokens, or key material.
var sensitiveArgNames = map[string]struct{}{
	"private_key":          {},
	"private_key_out":      {},
	"integrity_public_key": {},
	"public_key_out":       {},
	"authorization":        {},
}

// sensitiveTokens are individual words that mark a compound flag name as
// sensitive when they appear as a discrete segment (split on _-.:).
// Only exact token matches apply — no substring matching.
var sensitiveTokens = map[string]struct{}{
	"token":      {},
	"secret":     {},
	"password":   {},
	"credential": {},
	"auth":       {},
	"bearer":     {},
	"key":        {},
}

// isSensitiveKey reports whether a flag name indicates its value is sensitive.
// Uses exact flag name matching and token-based matching only — no substring
// matching, which avoids false positives like "auth" matching "author".
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
	if _, ok := sensitiveArgNames[norm]; ok {
		return true
	}

	// Token match: split on separators, check each segment.
	tokens := strings.FieldsFunc(norm, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ':'
	})
	for _, t := range tokens {
		if _, ok := sensitiveTokens[t]; ok {
			return true
		}
	}

	return false
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
