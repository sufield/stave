package artifacts

import (
	"fmt"
	"io"

	packs "github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/catalogquality"
	"github.com/sufield/stave/internal/app/catalogsearch"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// This package has two independent format-dispatch sites with
// distinct payloads: control-catalog search results and the catalog
// quality report. Each gets its own Renderer interface keyed by the
// payload it renders; the factories share the format-string contract
// but the concrete types and dispatch tables are per-payload. Same
// shape as the multi-payload pattern in cmd/nep.
//
// Concrete implementations delegate to the existing write* helpers so
// the rendered bytes stay byte-identical to the pre-Renderer-pattern
// output.

// --- ControlsRenderer (search results) ---

// ControlsRenderer renders catalog-search results in the requested
// format.
type ControlsRenderer interface {
	Render(w io.Writer, results []catalogsearch.SearchResult) error
}

// ControlsJSONRenderer encodes the search results as indented JSON.
type ControlsJSONRenderer struct{}

// Render implements ControlsRenderer.
func (ControlsJSONRenderer) Render(w io.Writer, results []catalogsearch.SearchResult) error {
	if err := jsonutil.WriteIndented(w, results); err != nil {
		return fmt.Errorf("write search JSON: %w", err)
	}
	return nil
}

// ControlsTableRenderer writes the default human-readable table.
type ControlsTableRenderer struct{}

// Render implements ControlsRenderer.
func (ControlsTableRenderer) Render(w io.Writer, results []catalogsearch.SearchResult) error {
	return writeSearchTable(w, results)
}

// NewControlsRenderer maps a format string to its concrete renderer.
// Empty string maps to the default text table; unknown formats are an
// explicit error surfaced through the factory.
func NewControlsRenderer(format string) (ControlsRenderer, error) {
	switch format {
	case "json":
		return ControlsJSONRenderer{}, nil
	case "text", "":
		return ControlsTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json)", format)
}

// --- QualityRenderer (catalog quality report) ---

// QualityRenderer renders the catalog quality report in the requested
// format.
type QualityRenderer interface {
	Render(w io.Writer, report catalogquality.Report) error
}

// QualityJSONRenderer encodes the report as indented JSON.
type QualityJSONRenderer struct{}

// Render implements QualityRenderer.
func (QualityJSONRenderer) Render(w io.Writer, report catalogquality.Report) error {
	return writeQualityJSON(w, report)
}

// QualityTableRenderer writes the default human-readable table.
type QualityTableRenderer struct{}

// Render implements QualityRenderer.
func (QualityTableRenderer) Render(w io.Writer, report catalogquality.Report) error {
	writeQualityTable(w, report)
	return nil
}

// NewQualityRenderer maps a format string to its concrete renderer.
// Empty string maps to the default table; unknown formats are an
// explicit error surfaced through the factory.
func NewQualityRenderer(format string) (QualityRenderer, error) {
	switch format {
	case "json":
		return QualityJSONRenderer{}, nil
	case "table", "":
		return QualityTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: table, json)", format)
}

// --- PacksRenderer (built-in control packs list) ---

// PacksRenderer renders the control-packs list in the requested format.
type PacksRenderer interface {
	Render(w io.Writer, items []packs.Pack) error
}

// PacksJSONRenderer encodes the packs list as indented JSON.
type PacksJSONRenderer struct{}

// Render implements PacksRenderer.
func (PacksJSONRenderer) Render(w io.Writer, items []packs.Pack) error {
	if err := jsonutil.WriteIndented(w, items); err != nil {
		return fmt.Errorf("write packs JSON: %w", err)
	}
	return nil
}

// PacksTextRenderer writes the default human-readable packs list.
type PacksTextRenderer struct{}

// Render implements PacksRenderer.
func (PacksTextRenderer) Render(w io.Writer, items []packs.Pack) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "No packs found.")
		return err
	}
	for _, p := range items {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", p.Name, p.Description); err != nil {
			return err
		}
	}
	return nil
}

// NewPacksRenderer maps a format string to its concrete renderer. Only "json"
// selects JSON; every other value (text, "", and the advertised-but-here-
// unimplemented csv) renders as the text list, preserving the pre-factory
// `if OutputFormat == FormatJSON {…} else {text}` catch-all byte-for-byte.
func NewPacksRenderer(format string) PacksRenderer {
	if format == "json" {
		return PacksJSONRenderer{}
	}
	return PacksTextRenderer{}
}
