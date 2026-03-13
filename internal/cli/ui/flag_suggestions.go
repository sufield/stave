package ui

import (
	"fmt"
	"strings"
)

// SuggestFlagParseError augments a flag parsing error with a "Did you mean?" hint.
// It uses fuzzy matching to find the closest valid flag from the candidates list.
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

// extractUnknownFlag parses typical CLI error messages to isolate the faulty flag name.
func extractUnknownFlag(msg string) string {
	// Check for quoted tokens (e.g., unknown flag 'x' or "flag").
	for _, quote := range []string{"'", `"`} {
		if token, ok := extractBetween(msg, quote); ok {
			return normalize(token)
		}
	}

	// Fallback: identify the last word if it looks like a flag prefix.
	fields := strings.Fields(msg)
	if len(fields) > 0 {
		last := fields[len(fields)-1]
		if strings.HasPrefix(last, "-") {
			return normalize(last)
		}
	}

	return ""
}

// extractBetween finds the first instance of text wrapped in the provided quote string.
func extractBetween(s, quote string) (string, bool) {
	_, after, ok := strings.Cut(s, quote)
	if !ok {
		return "", false
	}
	before, _, ok := strings.Cut(after, quote)
	return before, ok
}

// normalize cleans a flag token for fuzzy comparison.
func normalize(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}

	// If the library reported a bare character (like: unknown flag 'x'),
	// prepend a dash so it matches against candidates like "-x".
	if len(token) == 1 && !strings.HasPrefix(token, "-") {
		return "-" + token
	}

	return token
}
