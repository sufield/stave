package graphcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	graphpkg "github.com/sufield/stave/internal/adapters/graph"
	"github.com/sufield/stave/internal/core/report"
)

// Renderer is the polymorphic format-dispatch interface for graph export.
// Concrete implementations delegate to graphpkg.MarshalSTIX / MarshalJSONLD /
// MarshalGraphML or to encoding/json for the default. Four formats: stix,
// jsonld, graphml, json (default).
type Renderer interface {
	Render(w io.Writer, g *graphpkg.GraphData) error
}

// STIXRenderer emits the graph in STIX 2.1 form.
type STIXRenderer struct{}

// Render implements Renderer.
func (STIXRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	if err := graphpkg.MarshalSTIX(w, g); err != nil {
		return fmt.Errorf("marshal STIX: %w", err)
	}
	return nil
}

// JSONLDRenderer emits the graph in JSON-LD form.
type JSONLDRenderer struct{}

// Render implements Renderer.
func (JSONLDRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	if err := graphpkg.MarshalJSONLD(w, g); err != nil {
		return fmt.Errorf("marshal JSON-LD: %w", err)
	}
	return nil
}

// GraphMLRenderer emits the graph in GraphML form.
type GraphMLRenderer struct{}

// Render implements Renderer.
func (GraphMLRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	if err := graphpkg.MarshalGraphML(w, g); err != nil {
		return fmt.Errorf("marshal GraphML: %w", err)
	}
	return nil
}

// JSONRenderer emits the graph as the package's native indented JSON — the
// default format when no other is selected.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, g *graphpkg.GraphData) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

// NewRenderer maps a format string to its concrete Renderer. Returns an error
// for unknown formats rather than silently falling back to JSON.
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

// ExportGraph parses an out.v0.1 assessment, builds the standards-based graph,
// and renders it in the requested format (json/stix/jsonld/graphml). A bad
// assessment JSON wraps [InputError] (exit 2); an unknown format and render
// failures stay plain (exit 4 — preserved from the pre-facade command).
func ExportGraph(assessmentData []byte, format, sourcePath string, now time.Time) ([]byte, error) {
	var assessment report.Assessment
	if err := json.Unmarshal(assessmentData, &assessment); err != nil {
		return nil, &InputError{fmt.Errorf("parse assessment: %w", err)}
	}

	g := graphpkg.Build(graphpkg.BuildInput{
		Findings:      assessment.Findings,
		ChainFindings: assessment.ChainFindings,
		Now:           now,
		SourcePath:    sourcePath,
	})

	renderer, err := NewRenderer(format)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := renderer.Render(&buf, g); err != nil {
		return nil, fmt.Errorf("render graph export: %w", err)
	}
	return buf.Bytes(), nil
}
