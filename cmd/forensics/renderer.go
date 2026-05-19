package forensics

import (
	"encoding/json"
	"fmt"
	"io"

	appforensics "github.com/sufield/stave/internal/app/forensics"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave forensics`. Concrete implementations delegate to
// writeTableTimeline / encoding/json.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, tl *appforensics.Timeline) error
}

// JSONRenderer encodes the timeline as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, tl *appforensics.Timeline) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(tl)
}

// TableRenderer writes the default human-readable timeline table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, tl *appforensics.Timeline) error {
	writeTableTimeline(w, tl)
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as a table. The explicit error matches the
// documented unification from renderer-pattern-debt.md.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}
