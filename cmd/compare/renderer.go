package compare

import (
	"encoding/json"
	"fmt"
	"io"

	appcompare "github.com/sufield/stave/internal/app/compare"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave compare`. Concrete implementations delegate to the
// appcompare.WriteMarkdown / WriteTable helpers and encoding/json so
// the rendered bytes are byte-identical to the pre-Renderer-pattern
// output. The only behavioural change is that unknown formats become
// an explicit factory error instead of falling through to table.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, result *appcompare.Result) error
}

// JSONRenderer encodes the result as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r *appcompare.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// MarkdownRenderer writes the markdown comparison report.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, r *appcompare.Result) error {
	appcompare.WriteMarkdown(w, r)
	return nil
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, r *appcompare.Result) error {
	appcompare.WriteTable(w, r)
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as table. The explicit error matches the
// documented unification from renderer-pattern-debt.md.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "markdown":
		return MarkdownRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | markdown)", format)
}
