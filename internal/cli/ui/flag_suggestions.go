package ui

import (
	"fmt"
	"strings"
)

// SuggestCommandError augments an "unknown command" error with a single
// best-match "Did you mean?" hint using the suggest package. Returns the
// original error unchanged if the error is not a command-not-found or no
// close match exists.
func SuggestCommandError(err error, commandNames []string) error {
	if err == nil || len(commandNames) == 0 {
		return err
	}

	unknown := extractUnknownCommand(err.Error())
	if unknown == "" {
		return err
	}

	suggestion := ClosestToken(unknown, commandNames)
	if suggestion == "" || suggestion == unknown {
		return err
	}

	return fmt.Errorf("unknown command %q\nDid you mean %q?", unknown, suggestion)
}

// extractUnknownCommand parses Cobra's "unknown command" error format:
//
//	unknown command "aply" for "stave"
func extractUnknownCommand(msg string) string {
	if !strings.HasPrefix(msg, "unknown command ") {
		return ""
	}
	if token, ok := extractBetween(msg, `"`); ok {
		return token
	}
	return ""
}

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
