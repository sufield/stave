package ui

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/pkg/suggest"
)

// OutputFormat represents a validated output format for command output.
type OutputFormat string

const (
	// OutputFormatJSON selects JSON output.
	OutputFormatJSON OutputFormat = "json"
	// OutputFormatText selects human-readable text output.
	OutputFormatText OutputFormat = "text"
	// OutputFormatSARIF selects SARIF v2.1.0 output for GitHub Code Scanning.
	OutputFormatSARIF OutputFormat = "sarif"
)

// ParseOutputFormat validates and returns an OutputFormat value.
func ParseOutputFormat(s string) (OutputFormat, error) {
	normalized := OutputFormat(normalizeToken(s))
	switch normalized {
	case OutputFormatJSON, OutputFormatText, OutputFormatSARIF:
		return normalized, nil
	default:
		valid := []string{string(OutputFormatText), string(OutputFormatJSON), string(OutputFormatSARIF)}
		if suggestion := closestToken(normalizeToken(s), valid); suggestion != "" {
			return "", fmt.Errorf("invalid --format %q (use text, json, or sarif)\nDid you mean %q?", s, suggestion)
		}
		return "", fmt.Errorf("invalid --format %q (use text, json, or sarif)", s)
	}
}

// String implements fmt.Stringer.
func (f OutputFormat) String() string {
	return string(f)
}

// IsJSON returns true if the format is JSON.
func (f OutputFormat) IsJSON() bool {
	return f == OutputFormatJSON
}

func normalizeToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func closestToken(input string, valid []string) string {
	return suggest.Closest(input, valid)
}
