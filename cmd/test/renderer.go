package test

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/controltest"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave test`. The signature takes results + summary together
// because every existing renderer (JSON, TAP, table) needs both —
// summary carries counts, results carry per-case detail. The table
// renderer also takes a Verbose flag for trace output, carried on
// the concrete type rather than the interface.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, results []controltest.Result, summary controltest.Summary) error
}

// JSONRenderer emits the test results as JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, results []controltest.Result, summary controltest.Summary) error {
	return writeJSON(w, results, summary)
}

// TAPRenderer emits the test results in the Test Anything Protocol
// format consumed by tap-aware CI runners.
type TAPRenderer struct{}

// Render implements Renderer.
func (TAPRenderer) Render(w io.Writer, results []controltest.Result, summary controltest.Summary) error {
	return writeTAP(w, results, summary)
}

// TableRenderer writes the default human-readable table. Carries
// Verbose state because the table renderer is the only one that
// surfaces per-case trace output.
type TableRenderer struct {
	Verbose bool
}

// Render implements Renderer.
func (r TableRenderer) Render(w io.Writer, results []controltest.Result, summary controltest.Summary) error {
	return writeTable(w, results, summary, r.Verbose)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as a table. The explicit error matches the
// documented unification from renderer-pattern-debt.md.
func NewRenderer(format string, verbose bool) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "tap":
		return TAPRenderer{}, nil
	case "table", "":
		return TableRenderer{Verbose: verbose}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | tap)", format)
}
