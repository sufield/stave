package ui

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// OutputFormat is an alias for appcontracts.OutputFormat so that existing cmd/
// code referencing ui.OutputFormat continues to compile without changes.
type OutputFormat = appcontracts.OutputFormat

const (
	// OutputFormatJSON selects JSON output.
	OutputFormatJSON = appcontracts.FormatJSON
	// OutputFormatText selects human-readable text output.
	OutputFormatText = appcontracts.FormatText
	// OutputFormatSARIF selects SARIF v2.1.0 output for GitHub Code Scanning.
	OutputFormatSARIF = appcontracts.FormatSARIF
	// OutputFormatMarkdown selects Markdown output (headings + pipe tables).
	OutputFormatMarkdown = appcontracts.FormatMarkdown
)

// ParseOutputFormat validates and returns an OutputFormat value.
func ParseOutputFormat(s string) (OutputFormat, error) {
	normalized := OutputFormat(NormalizeToken(s))
	switch normalized {
	case OutputFormatJSON, OutputFormatText, OutputFormatSARIF, OutputFormatMarkdown:
		return normalized, nil
	default:
		valid := []string{string(OutputFormatText), string(OutputFormatJSON), string(OutputFormatSARIF), string(OutputFormatMarkdown)}
		if suggestion := ClosestToken(NormalizeToken(s), valid); suggestion != "" {
			return "", fmt.Errorf("invalid --format %q (use text, json, sarif, or markdown)\nDid you mean %q?", s, suggestion)
		}
		return "", fmt.Errorf("invalid --format %q (use text, json, sarif, or markdown)", s)
	}
}
