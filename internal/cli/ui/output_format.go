package ui

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// ParseOutputFormat validates and returns an OutputFormat value.
func ParseOutputFormat(s string) (appcontracts.OutputFormat, error) {
	normalized := appcontracts.OutputFormat(NormalizeToken(s))
	switch normalized {
	case appcontracts.FormatJSON, appcontracts.FormatText, appcontracts.FormatSARIF, appcontracts.FormatMarkdown:
		return normalized, nil
	default:
		valid := []string{string(appcontracts.FormatText), string(appcontracts.FormatJSON), string(appcontracts.FormatSARIF), string(appcontracts.FormatMarkdown)}
		if suggestion := ClosestToken(NormalizeToken(s), valid); suggestion != "" {
			return "", fmt.Errorf("invalid --format %q (use text, json, sarif, or markdown)\nDid you mean %q?", s, suggestion)
		}
		return "", fmt.Errorf("invalid --format %q (use text, json, sarif, or markdown)", s)
	}
}
