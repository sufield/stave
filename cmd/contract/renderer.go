package contract

import (
	"fmt"
	"io"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave contract`. Unlike most commands in this repo, contract has
// two different payload types (typeReport for per-asset-type detail,
// listReport for the catalog list). The renderer takes `any` and
// each concrete TextRenderer type-switches; JSONRenderer just hands
// the value to writeJSON, which already accepts any.
//
// This mirrors cmd/export/compliance/renderer.go's shape — that
// command also has two payload variants behind a single Renderer.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, payload any) error
}

// JSONRenderer encodes any payload as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, payload any) error {
	return writeJSON(w, payload)
}

// TextRenderer dispatches to the per-type-of-payload text helper.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, payload any) error {
	switch p := payload.(type) {
	case typeReport:
		return writeTypeText(w, p)
	case listReport:
		return writeListText(w, p)
	}
	return fmt.Errorf("text renderer: unsupported payload type %T", payload)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous run() body had
// a validation switch at the top with this exact message.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("--format must be text | json (got %q)", format)
}
