package graph

import (
	"bytes"
	"fmt"
)

// FindingsGraph is the public alias the user named in the spec. It
// refers to the same shape the rest of the package builds via
// graph.Build — kept as a separate name so external tooling can
// import the export-stable identifier without depending on the
// internal type alias drift.
type FindingsGraph = GraphData

// GraphExporter is the serializer-agnostic interface for emitting a
// FindingsGraph. Each concrete exporter writes its own format; the
// caller supplies the graph and gets back the serialized bytes.
//
// The interface returns []byte rather than streaming to an io.Writer
// because the spec requires it. Where streaming matters (very large
// graphs, pipes), callers can reach for MarshalJSONLD / MarshalGraphML
// directly — both accept io.Writer.
type GraphExporter interface {
	Export(graph *FindingsGraph) ([]byte, error)
}

// JSONLDExporter implements GraphExporter for JSON-LD output. The
// embedded Format field is informational only; consumers that
// negotiate format strings can use it to assert the exporter
// matches.
type JSONLDExporter struct {
	Format string // "jsonld"
}

// NewJSONLDExporter returns a JSON-LD GraphExporter.
func NewJSONLDExporter() *JSONLDExporter { return &JSONLDExporter{Format: "jsonld"} }

// Export serializes the graph as JSON-LD bound to the embedded Stave
// ontology. The returned bytes are a single JSON document with
// @context and @graph; see ontology.ttl for the term definitions
// and shortcut-edge annotations.
func (e *JSONLDExporter) Export(graph *FindingsGraph) ([]byte, error) {
	var buf bytes.Buffer
	if err := MarshalJSONLD(&buf, graph); err != nil {
		return nil, fmt.Errorf("export jsonld: %w", err)
	}
	return buf.Bytes(), nil
}

// GraphMLExporter implements GraphExporter for GraphML XML output.
type GraphMLExporter struct {
	Format string // "graphml"
}

// NewGraphMLExporter returns a GraphML GraphExporter.
func NewGraphMLExporter() *GraphMLExporter { return &GraphMLExporter{Format: "graphml"} }

// Export serializes the graph as GraphML XML. Schema-first: typed
// <key> declarations precede the <graph> body so consumers know the
// data types of every attribute up front.
func (e *GraphMLExporter) Export(graph *FindingsGraph) ([]byte, error) {
	var buf bytes.Buffer
	if err := MarshalGraphML(&buf, graph); err != nil {
		return nil, fmt.Errorf("export graphml: %w", err)
	}
	return buf.Bytes(), nil
}

// Compile-time interface checks.
var (
	_ GraphExporter = (*JSONLDExporter)(nil)
	_ GraphExporter = (*GraphMLExporter)(nil)
)
