package fingerprint

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/pkg/stave"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave fingerprint explain`. Concrete implementations delegate to
// encoding/json or fmt.Fprintln so the rendered bytes are
// byte-identical to the pre-Renderer-pattern output.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, result *stave.FingerprintExplainResult) error
}

// JSONRenderer encodes the result as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, result *stave.FingerprintExplainResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode fingerprint JSON: %w", err)
	}
	return nil
}

// TextRenderer writes the default human-readable preimage and
// fingerprint lines.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, result *stave.FingerprintExplainResult) error {
	fmt.Fprintln(w, result.Preimage)
	fmt.Fprintln(w, result.Fingerprint)
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats so a bad --format surfaces
// as an explicit input error at the factory.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json)", format)
}
