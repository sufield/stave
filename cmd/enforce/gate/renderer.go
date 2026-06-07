package gate

import (
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/util/jsonutil"
	"github.com/sufield/stave/pkg/stave"
)

// Renderer is the polymorphic format-dispatch interface for the CI
// gate command. Concrete implementations delegate to jsonutil for the
// JSON wire format or fmt for the text summary.
//
// Two formats: text (default) and json. The quiet flag is carried on
// the text renderer because suppression only applies to the human
// summary — the JSON wire format is always emitted so downstream gates
// and scripts get a parseable result regardless of --quiet.
type Renderer interface {
	Render(w io.Writer, result *stave.GateResult) error
}

// gateJSON is the wire-format envelope for the JSON output. Field
// names and time-encoding match the prior usecase.GateResponse shape
// (time.Time's default RFC3339Nano marshaling) so existing CI scripts
// that grep `pass` or `current_violations` continue to work after
// the migration.
type gateJSON struct {
	Policy            string    `json:"policy"`
	Pass              bool      `json:"pass"`
	Reason            string    `json:"reason"`
	CheckedAt         time.Time `json:"checked_at"`
	CurrentViolations int       `json:"current_violations,omitempty"`
	NewViolations     int       `json:"new_violations,omitempty"`
	OverdueUpcoming   int       `json:"overdue_upcoming,omitempty"`
}

// JSONRenderer emits the gate result as indented JSON through
// gateJSON so the wire format stays compatible with the previous
// usecase.GateResponse shape — operators running the JSON output
// through scripts or downstream gates rely on those exact field names.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, result *stave.GateResult) error {
	if err := jsonutil.WriteIndented(w, gateJSON{
		Policy:            string(result.Policy),
		Pass:              result.Passed,
		Reason:            result.Reason,
		CheckedAt:         result.CheckedAt,
		CurrentViolations: result.CurrentViolations,
		NewViolations:     result.NewViolations,
		OverdueUpcoming:   result.OverdueCount,
	}); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// TextRenderer writes the human-readable gate summary. When Quiet is
// set it suppresses the summary entirely (exit code only).
type TextRenderer struct {
	Quiet bool
}

// Render implements Renderer.
func (t TextRenderer) Render(w io.Writer, result *stave.GateResult) error {
	if t.Quiet {
		return nil
	}
	_, err := fmt.Fprintf(w, "Gate %s (%s): %s\n", result.PassLabel(), result.Policy, result.Reason)
	return err
}

// NewRenderer maps a contracts.OutputFormat to its concrete Renderer.
// The quiet flag scopes text suppression; it is ignored for JSON,
// which always emits its wire format. Returns an error for unsupported
// formats — this is defensive: --format is validated upstream at parse
// time, so an unknown value here signals a programming error rather
// than bad user input.
func NewRenderer(format contracts.OutputFormat, quiet bool) (Renderer, error) {
	switch format {
	case contracts.FormatJSON:
		return JSONRenderer{}, nil
	case contracts.FormatText, "":
		return TextRenderer{Quiet: quiet}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
