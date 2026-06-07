package alias

import (
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave alias list`. Concrete implementations delegate to
// jsonutil.WriteIndented for JSON or print the human-readable
// text listing.
//
// Two formats: json, text (default).
type Renderer interface {
	Render(w io.Writer, entries []Entry) error
}

// JSONRenderer emits the alias entries as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, entries []Entry) error {
	if entries == nil {
		entries = []Entry{}
	}
	if err := jsonutil.WriteIndented(w, entries); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// TextRenderer emits the alias entries as human-readable text.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, entries []Entry) error {
	if len(entries) == 0 {
		fmt.Fprintln(w, "No aliases defined.")
		return nil
	}
	for _, e := range entries {
		fmt.Fprintf(w, "%s -> %s\n", e.Name, e.Command)
	}
	return nil
}

// NewRenderer maps a typed OutputFormat to its concrete Renderer.
// The enum is validated upstream at flag-parse time, so an unknown
// format here is defensive — return an explicit error rather than a
// silent JSON fallback.
func NewRenderer(format cmdutil.OutputFormat) (Renderer, error) {
	switch format {
	case cmdutil.FormatJSON:
		return JSONRenderer{}, nil
	case cmdutil.FormatText:
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text or json)", format)
}
