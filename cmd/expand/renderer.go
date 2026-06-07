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
	Archetype      archetype.Archetype
	Matched        []policy.ControlDefinition
	SnapshotStatus *expand.SnapshotStatus
	Finding        *policy.ControlDefinition
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

// --- ListRenderer ---
//
// `stave expand --list` renders a different payload (the archetype
// catalog summary derived from the loaded controls) than the
// single-archetype expand above. Following the multi-payload
// convention (cmd/nep, cmd/consolidate), it gets its own Renderer
// interface keyed by its payload type and a sibling factory sharing
// the same format-string contract.

// ListRenderer is the polymorphic format-dispatch interface for
// `stave expand --list`. Concrete implementations delegate to the
// existing renderListText / renderListJSON helpers, which are
// unchanged.
type ListRenderer interface {
	Render(w io.Writer, controls []policy.ControlDefinition) error
}

// ListJSONRenderer emits the archetype catalog summary as JSON.
type ListJSONRenderer struct{}

// Render implements ListRenderer.
func (ListJSONRenderer) Render(w io.Writer, controls []policy.ControlDefinition) error {
	return renderListJSON(w, controls)
}

// ListTextRenderer emits the default human-readable catalog summary.
type ListTextRenderer struct{}

// Render implements ListRenderer.
func (ListTextRenderer) Render(w io.Writer, controls []policy.ControlDefinition) error {
	return renderListText(w, controls)
}

// NewListRenderer maps a format string to its concrete ListRenderer.
func NewListRenderer(format string) (ListRenderer, error) {
	switch format {
	case "json":
		return ListJSONRenderer{}, nil
	case "text", "":
		return ListTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
