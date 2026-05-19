package validatemapping

import (
	"encoding/json"
	"fmt"
	"io"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave validate-mapping`. Concrete implementations delegate to
// writeText (cmd/validatemapping/cmd.go) and encoding/json. The
// validation switch + `if format == "json"` dispatch that bracketed
// the run() body collapses to a single NewRenderer call at the top.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r report) error
}

// JSONRenderer encodes the report as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// TextRenderer writes the human-readable validation report.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, r report) error {
	return writeText(w, r)
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
