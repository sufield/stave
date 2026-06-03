package apply

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/findingfilter"
)

// NewOnlyRenderer is the polymorphic format-dispatch interface for
// `stave apply` in new-only mode. Distinct from a top-level
// `Renderer` because the cmd/apply package owns multiple output
// surfaces (main apply, new-only filter, plus exit-code reasoning);
// each surface gets its own narrow interface rather than one
// over-general one that wouldn't fit the next migration.
//
// Two formats: json + the default human-readable text.
type NewOnlyRenderer interface {
	Render(w io.Writer, r *findingfilter.Result) error
}

// NewOnlyJSONRenderer encodes the filter result as indented JSON.
type NewOnlyJSONRenderer struct{}

// Render implements NewOnlyRenderer.
func (NewOnlyJSONRenderer) Render(w io.Writer, r *findingfilter.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// NewOnlyTextRenderer writes the default human-readable summary.
type NewOnlyTextRenderer struct{}

// Render implements NewOnlyRenderer.
func (NewOnlyTextRenderer) Render(w io.Writer, r *findingfilter.Result) error {
	return writeNewOnlyText(w, r)
}

// NewNewOnlyRenderer maps a format string to its concrete renderer.
// Returns an error for unknown formats; the previous default branch
// silently fell through to text rendering.
func NewNewOnlyRenderer(format string) (NewOnlyRenderer, error) {
	switch format {
	case "json":
		return NewOnlyJSONRenderer{}, nil
	case "text", "":
		return NewOnlyTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
