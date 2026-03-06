package ui

import (
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
