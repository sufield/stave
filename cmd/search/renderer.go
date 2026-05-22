package search

import (
	"fmt"
	"io"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// searchReport is the JSON-shape contract for `stave search`.
// Extracted from an inline anonymous struct so the renderer has a
// named payload type — making the JSON contract grep-able and
// stable across the migration.
type searchReport struct {
	Query string        `json:"query"`
	Top   int           `json:"top"`
	Total int           `json:"total_hits"`
	Hits  []appcaps.Hit `json:"hits"`
}

// Renderer is the polymorphic format-dispatch interface for
// `stave search`. The validation switch + `if format == "json"`
// dispatch in run() collapse to a single NewRenderer call at the top.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r searchReport) error
}

// JSONRenderer encodes the report via jsonutil.WriteIndented.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r searchReport) error {
	return jsonutil.WriteIndented(w, r)
}

// TextRenderer writes the human-readable search results.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, r searchReport) error {
	return renderText(w, r.Query, r.Hits)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous validation
// switch had this exact message.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("--format must be text | json (got %q)", format)
}
