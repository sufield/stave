package ui

import (
	"fmt"
	"strings"
)

// SuggestFlagParseError augments unknown-flag parse errors with the nearest
// suggestion from the provided candidate list. The caller is responsible for
// collecting candidates (e.g. from a cobra.Command's flag set).
func SuggestFlagParseError(parseErr error, candidates []string) error {
	if parseErr == nil || len(candidates) == 0 {
		return parseErr
	}

	unknown := extractUnknownFlag(parseErr.Error())
	if unknown == "" {
		return parseErr
	}

	suggestion := ClosestToken(unknown, candidates)
	if suggestion == "" || strings.EqualFold(suggestion, unknown) {
		return parseErr
	}

	return fmt.Errorf("%w\nDid you mean %q?", parseErr, suggestion)
}

// extractUnknownFlag extracts the flag token from a pflag/cobra error message.
// It first tries to find a quoted token (single or double quotes), then falls
// back to the last word if it looks like a flag (starts with "-").
func extractUnknownFlag(msg string) string {
	lower := strings.ToLower(strings.TrimSpace(msg))

	// Try single-quoted token (pflag shorthand format: 'x' in -x)
	if token := extractQuotedToken(lower, "'"); token != "" {
		return normalizeFlagToken(token)
	}
	// Try double-quoted token
	if token := extractQuotedToken(lower, `"`); token != "" {
		return normalizeFlagToken(token)
	}

	// Fallback: last word if it looks like a flag
	fields := strings.Fields(lower)
	if len(fields) > 0 {
		last := fields[len(fields)-1]
		if strings.HasPrefix(last, "-") {
			return last
		}
	}
	return ""
}

// extractQuotedToken returns the content between the first pair of quote characters.
func extractQuotedToken(msg, quote string) string {
	_, after, ok := strings.Cut(msg, quote)
	if !ok {
		return ""
	}
	rest := after
	before, _, ok := strings.Cut(rest, quote)
	if !ok {
		return ""
	}
	return before
}

// normalizeFlagToken ensures a bare single character gets a "-" prefix.
func normalizeFlagToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if !strings.HasPrefix(token, "-") && len(token) == 1 {
		return "-" + token
	}
	return token
}
