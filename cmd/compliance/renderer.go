package compliance

import (
	"encoding/json"
	"fmt"
	"io"

	cm "github.com/sufield/stave/internal/compliancemapping"
)

// Renderer is the format-dispatch interface for `stave compliance`.
// New formats add an implementation here and a case in NewRenderer.
type Renderer interface {
	Render(w io.Writer, r *cm.Report) error
}

// NewRenderer maps a format string to its concrete Renderer. Unknown formats
// surface as an explicit input error at the factory (exit 2).
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "text", "":
		return TextRenderer{}, nil
	case "json":
		return JSONRenderer{}, nil
	case "markdown", "md":
		return MarkdownRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json, markdown)", format)
}

// JSONRenderer emits the full machine-readable report for auditor consumption.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *cm.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode compliance JSON: %w", err)
	}
	return nil
}

// TextRenderer writes the three-section human-readable display.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, r *cm.Report) error {
	fmt.Fprintf(w, "%s %s — compliance coverage\n\n", r.Framework, r.FrameworkVersion)

	fmt.Fprintf(w, "✅ COVERED (%d controls)\n", len(r.Covered))
	for i := range r.Covered {
		c := &r.Covered[i]
		fmt.Fprintf(w, "  %-8s %-44s %s (%s)\n", c.ID, truncate(c.Title, 44), c.Status, coveredDetail(c))
	}

	fmt.Fprintf(w, "\n⚠️  GAPS (%d controls in scope, no Stave control yet)\n", len(r.Gaps))
	for i := range r.Gaps {
		c := &r.Gaps[i]
		fmt.Fprintf(w, "  %-8s %-44s NOT VERIFIED (no control in catalog)\n", c.ID, truncate(c.Title, 44))
	}

	fmt.Fprintf(w, "\n⬜ OUT OF SCOPE (%d controls — organizational/runtime/physical)\n", len(r.OutOfScope))
	for i := range r.OutOfScope {
		c := &r.OutOfScope[i]
		fmt.Fprintf(w, "  %-8s %-44s %s\n", c.ID, truncate(c.Title, 44), c.OutOfScopeKind)
	}

	fmt.Fprintf(w, "\nCoverage: %d of %d in-scope controls have Stave verification (%.0f%%)\n",
		r.Verified, r.InScope, r.CoveragePercent)
	if r.Failed > 0 {
		fmt.Fprintf(w, "Failures: %d covered control(s) FAIL — fix these findings first.\n", r.Failed)
	}
	return nil
}

func coveredDetail(c *cm.ControlResult) string {
	if c.Status == cm.StatusFail {
		return fmt.Sprintf("%d Stave control(s) failed", len(c.FailedControls))
	}
	n := len(c.StaveControls)
	if c.Partial {
		return fmt.Sprintf("%d control(s) verified, partial mapping", n)
	}
	return fmt.Sprintf("%d Stave control(s) verified", n)
}

// MarkdownRenderer writes a report suitable for documentation/auditor handoff.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, r *cm.Report) error {
	fmt.Fprintf(w, "# %s %s — Compliance Coverage\n\n", r.Framework, r.FrameworkVersion)
	fmt.Fprintf(w, "**Coverage: %d of %d in-scope controls verified (%.0f%%)** — %d passed, %d failed.\n\n",
		r.Verified, r.InScope, r.CoveragePercent, r.Passed, r.Failed)

	fmt.Fprintf(w, "## ✅ Covered (%d)\n\n", len(r.Covered))
	fmt.Fprintln(w, "| Control | Title | Status | Stave controls |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for i := range r.Covered {
		c := &r.Covered[i]
		status := string(c.Status)
		if c.Partial {
			status += " (partial)"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", c.ID, mdEsc(c.Title), status, mdControls(c))
	}

	fmt.Fprintf(w, "\n## ⚠️ Gaps — in scope, no Stave control yet (%d)\n\n", len(r.Gaps))
	fmt.Fprintln(w, "| Control | Title | What a Stave control should check |")
	fmt.Fprintln(w, "|---|---|---|")
	for i := range r.Gaps {
		c := &r.Gaps[i]
		fmt.Fprintf(w, "| %s | %s | %s |\n", c.ID, mdEsc(c.Title), mdEsc(c.Detail))
	}

	fmt.Fprintf(w, "\n## ⬜ Out of scope (%d)\n\n", len(r.OutOfScope))
	fmt.Fprintln(w, "| Control | Title | Kind |")
	fmt.Fprintln(w, "|---|---|---|")
	for i := range r.OutOfScope {
		c := &r.OutOfScope[i]
		fmt.Fprintf(w, "| %s | %s | %s |\n", c.ID, mdEsc(c.Title), c.OutOfScopeKind)
	}
	return nil
}

func mdControls(c *cm.ControlResult) string {
	if c.Status == cm.StatusFail {
		return "FAILED: " + join(c.FailedControls)
	}
	return join(c.StaveControls)
}
