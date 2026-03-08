package ui

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/pkg/suggest"
)

// NormalizeToken returns a trimmed lowercase token for matching.
func NormalizeToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// ClosestToken returns the nearest candidate based on edit distance.
func ClosestToken(input string, valid []string) string {
	return suggest.Closest(input, valid)
}

// EnumError returns a formatted error for an invalid enum value,
// including a "Did you mean?" suggestion if a close match exists.
func EnumError(flag, raw string, valid []string) error {
	if suggestion := ClosestToken(NormalizeToken(raw), valid); suggestion != "" {
		return fmt.Errorf("invalid %s %q (%s)\nDid you mean %q?", flag, raw, enumList(valid), suggestion)
	}
	return fmt.Errorf("invalid %s %q (%s)", flag, raw, enumList(valid))
}

// enumList formats valid options as "use a, b, or c".
func enumList(valid []string) string {
	switch len(valid) {
	case 0:
		return ""
	case 1:
		return "use " + valid[0]
	case 2:
		return "use " + valid[0] + " or " + valid[1]
	default:
		return "use " + strings.Join(valid[:len(valid)-1], ", ") + ", or " + valid[len(valid)-1]
	}
}
