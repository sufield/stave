package cmd

import (
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// SchemasRenderer is the format-dispatch interface for `stave schemas`.
// Concrete implementations delegate to jsonutil.WriteIndented (JSON) or
// the package's existing text renderer (text). Two formats: json, text.
//
// The "renderer" filename prefix keeps the renderer-pattern guard test
// (renderer_pattern_test.go) from scanning the factory's format switch.
type SchemasRenderer interface {
	Render(w io.Writer, out schemasOutput) error
}

// schemasJSONRenderer emits the schema listing as indented JSON.
type schemasJSONRenderer struct{}

// Render implements SchemasRenderer.
func (schemasJSONRenderer) Render(w io.Writer, out schemasOutput) error {
	if err := jsonutil.WriteIndented(w, out); err != nil {
		return fmt.Errorf("write schemas JSON: %w", err)
	}
	return nil
}

// schemasTextRenderer emits the schema listing as grouped, column-aligned
// human-readable text.
type schemasTextRenderer struct{}

// Render implements SchemasRenderer.
func (schemasTextRenderer) Render(w io.Writer, out schemasOutput) error {
	return renderSchemasText(w, out)
}

// NewSchemasRenderer maps a typed OutputFormat to its concrete
// SchemasRenderer. Unknown formats return an explicit error; the format
// enum is validated upstream at the flag boundary, so this branch is
// defensive.
func NewSchemasRenderer(format appcontracts.OutputFormat) (SchemasRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return schemasJSONRenderer{}, nil
	case appcontracts.FormatText:
		return schemasTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
