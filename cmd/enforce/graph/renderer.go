package graph

import (
	"encoding/json"
	"fmt"
	"io"

	graphpkg "github.com/sufield/stave/internal/adapters/graph"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave graph export`. Concrete implementations delegate to
// graphpkg.MarshalSTIX / MarshalJSONLD / MarshalGraphML or to
// encoding/json for the default.
//
// Four formats: stix, jsonld, graphml, json (default).
type Renderer interface {
	Render(w io.Writer, g *graphpkg.GraphData) error
}

// STIXRenderer emits the graph in STIX 2.1 form.
type STIXRenderer struct{}

// Render implements Renderer.
func (STIXRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	return graphpkg.MarshalSTIX(w, g)
}

// JSONLDRenderer emits the graph in JSON-LD form.
type JSONLDRenderer struct{}

// Render implements Renderer.
func (JSONLDRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	return graphpkg.MarshalJSONLD(w, g)
}

// GraphMLRenderer emits the graph in GraphML form.
type GraphMLRenderer struct{}

// Render implements Renderer.
func (GraphMLRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	return graphpkg.MarshalGraphML(w, g)
}

// JSONRenderer emits the graph as the package's native indented JSON
// — the default format when no other is selected.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the previous default branch
// silently rendered as JSON, which masked typos like "stix2" ->
// "json fallback".
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "stix":
		return STIXRenderer{}, nil
	case "jsonld":
		return JSONLDRenderer{}, nil
	case "graphml":
		return GraphMLRenderer{}, nil
	case "json", "":
		return JSONRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: json | stix | jsonld | graphml)", format)
}
