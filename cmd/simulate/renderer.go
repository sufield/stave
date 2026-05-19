package simulate

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	appsim "github.com/sufield/stave/internal/app/simulate"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave simulate`. Concrete implementations carry whatever
// per-format state they need (the text renderer carries the input
// fix list because the header line names it; the simulate Result
// does not).
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, result *appsim.Result) error
}

// JSONRenderer encodes the result as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *appsim.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// TextRenderer writes the default human-readable text report. Carries
// the input fix list because the report header names the controls
// being simulated and that input lives outside the Result struct.
type TextRenderer struct {
	Fix []string
}

// Render implements Renderer.
func (r TextRenderer) Render(w io.Writer, result *appsim.Result) error {
	writeText(w, result, r.Fix)
	return nil
}

// writeText emits the text-format simulation report. Extracted from
// the pre-Renderer-pattern inline branch so the rendering can be
// tested directly and reused if simulate ever grows a second text-
// shaped format.
func writeText(w io.Writer, result *appsim.Result, fix []string) {
	fmt.Fprintf(w, "REMEDIATION SIMULATION\nFixing: %s\n\n", strings.Join(fix, ", "))
	fmt.Fprintf(w, "POSTURE SCORE\n  Current:    %.1f\n  Simulated:  %.1f  (%+.1f)\n\n",
		result.ScoreCurrent, result.ScoreSimulated, result.ScoreDelta)
	if len(result.ChainsDeactivated) > 0 {
		fmt.Fprintln(w, "CHAINS DEACTIVATED")
		for _, c := range result.ChainsDeactivated {
			fmt.Fprintf(w, "  %-40s %s → %s\n", c.ChainID, c.DisplaySeverity(), c.Status)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "FINDINGS ELIMINATED: %d\n", result.FindingsRemoved)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as text. The explicit error matches the
// documented unification from renderer-pattern-debt.md.
func NewRenderer(format string, fix []string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{Fix: fix}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
