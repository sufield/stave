package reporter

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// New returns the appropriate Reporter for the given output format.
// Replaces the inline switch repeated across cmd/evaluate, cmd/report,
// cmd/plan, cmd/budget, and cmd/score.
//
// The format argument accepts both string forms ("text", "json") and
// appcontracts.OutputFormat — callers that already parsed the format
// can pass through; callers reading raw flag values can pass the string
// directly.
func New(format string) (Reporter, error) {
	switch appcontracts.OutputFormat(format) {
	case appcontracts.FormatJSON:
		return JSONReporter{}, nil
	case appcontracts.FormatText, "":
		return TextReporter{}, nil
	}
	return nil, fmt.Errorf("unsupported reporter format %q (use: text, json)", format)
}
