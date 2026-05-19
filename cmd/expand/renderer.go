package expand

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/adapters/controls/archetype"
	"github.com/sufield/stave/internal/app/expand"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// Payload bundles the four arguments every renderer needs so the
// Renderer interface stays a single-payload contract. The fields
// match the renderJSON / renderText signatures from before the
// migration; bundling them here means new formats add one
// implementation rather than a new function-call shape.
type Payload struct {
	Archetype       archetype.Archetype
	Matched         []policy.ControlDefinition
	SnapshotStatus  *expand.SnapshotStatus
	Finding         *policy.ControlDefinition
}

// Renderer is the polymorphic format-dispatch interface for
// `stave expand`. Concrete implementations delegate to the existing
// renderText / renderJSON helpers, which are unchanged.
type Renderer interface {
	Render(w io.Writer, p Payload) error
}

// JSONRenderer emits the expand output as JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, p Payload) error {
	return renderJSON(w, p.Archetype, p.Matched, p.SnapshotStatus, p.Finding)
}

// TextRenderer emits the default human-readable text.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, p Payload) error {
	return renderText(w, p.Archetype, p.Matched, p.SnapshotStatus, p.Finding)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as text. The explicit error matches the
// documented unification from renderer-pattern-debt.md.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
