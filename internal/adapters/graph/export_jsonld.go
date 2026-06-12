package graph

import (
	"bufio"
	"bytes"
	"cmp"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
)

//go:embed ontology.ttl
var embeddedOntology []byte

// Ontology returns the embedded Stave ontology as Turtle bytes.
// Callers that need to ship the ontology alongside an export use
// this directly. Returns a defensive copy so a write through the
// returned slice cannot corrupt the process-shared embedded bytes.
func Ontology() []byte {
	out := make([]byte, len(embeddedOntology))
	copy(out, embeddedOntology)
	return out
}

// MarshalJSONLD writes a JSON-LD document for the graph. The output
// is one JSON object with @context (binding short names from the
// Stave ontology to full IRIs) and @graph (a flat array of subject
// objects, each carrying its outgoing predicates as nested IRI
// references). Algorithm-shortcut edges are annotated with
// "stave:isAlgorithmShortcut": true so consumers can filter the
// shortcut subgraph for GDS workloads.
//
// The serializer is hand-rolled — no JSON-LD framework — and
// streams via a *bufio.Writer to keep allocations bounded for
// large graphs.
func MarshalJSONLD(w io.Writer, g *GraphData) error {
	unmapped, err := MarshalJSONLDWithDiagnostics(w, g)
	if err != nil {
		return err
	}
	// Surface dropped edges through the structured logger so a
	// silent-drop case (vocabulary drift, unrecognised predicate
	// type) is visible to operators rather than disappearing into
	// the discarded diagnostic slice.
	if len(unmapped) > 0 {
		slog.Warn("jsonld export: unmapped edges dropped",
			"count", len(unmapped))
	}
	return nil
}

// MarshalJSONLDWithDiagnostics is the same as MarshalJSONLD but
// also returns the list of edges that were dropped because their
// Type was not in the wireToPredicate vocabulary. Callers wanting
// strict-mode export check the returned slice for non-empty.
func MarshalJSONLDWithDiagnostics(w io.Writer, g *GraphData) ([]UnmappedEdge, error) {
	if g == nil {
		return nil, errors.New("marshalJSONLD: nil GraphData")
	}
	rdf := mapTordfGraph(g)

	// Group edges by subject IRI so the document is one node per
	// subject with all outgoing properties inline. JSON-LD's @graph
	// can hold flat triples too, but the grouped form is what tools
	// like rdflib's parse() expect to see by default and is also
	// half the byte count.
	edgesBySubject := make(map[string][]rdfEdge, len(rdf.Nodes))
	for i := range rdf.Edges {
		e := &rdf.Edges[i]
		edgesBySubject[e.From] = append(edgesBySubject[e.From], *e)
	}

	bw := bufio.NewWriter(w)

	// Write the document opening, @context, and @graph header by hand
	// rather than constructing the full document in memory. This
	// matters because @graph itself is the big array.
	if _, err := bw.WriteString(jsonldHeader); err != nil {
		return rdf.UnmappedEdges, fmt.Errorf("write jsonld header: %w", err)
	}

	first := true
	enc := newJSONLDNodeEncoder()
	for i := range rdf.Nodes {
		n := &rdf.Nodes[i]
		out := enc.encodeNode(n, edgesBySubject[n.ID])
		if !first {
			if _, err := bw.WriteString(",\n"); err != nil {
				return rdf.UnmappedEdges, fmt.Errorf("write jsonld separator: %w", err)
			}
		}
		if _, err := bw.Write(out); err != nil {
			return rdf.UnmappedEdges, fmt.Errorf("write jsonld node: %w", err)
		}
		first = false
	}
	if _, err := bw.WriteString(jsonldFooter); err != nil {
		return rdf.UnmappedEdges, fmt.Errorf("write jsonld footer: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return rdf.UnmappedEdges, fmt.Errorf("flush jsonld output: %w", err)
	}
	return rdf.UnmappedEdges, nil
}

// jsonldHeader is the literal start of the JSON-LD output. The
// @context binds the short names used in the document body to their
// full IRIs so downstream parsers can expand the document into RDF
// triples. The "@vocab" binding makes any unqualified property name
// in the body resolve relative to the Stave ontology — that lets
// node datatype properties (severity, weight, account_id) appear as
// bare keys instead of every key needing to be explicitly mapped.
//
// Indented for human readability; the @graph body starts on a new
// line so the streaming writer can append node objects directly.
const jsonldHeader = `{
  "@context": {
    "@vocab": "urn:stave:ontology#",
    "stave": "urn:stave:ontology#",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "owl": "http://www.w3.org/2002/07/owl#",
    "id": "@id",
    "type": "@type",
    "targets": { "@id": "stave:targets", "@type": "@id" },
    "violatesInvariant": { "@id": "stave:violatesInvariant", "@type": "@id" },
    "violates": { "@id": "stave:violates", "@type": "@id" },
    "violatesRequirement": { "@id": "stave:violatesRequirement", "@type": "@id" },
    "mapsTo": { "@id": "stave:mapsTo", "@type": "@id" },
    "hasRemediation": { "@id": "stave:hasRemediation", "@type": "@id" },
    "memberOf": { "@id": "stave:memberOf", "@type": "@id" },
    "produces": { "@id": "stave:produces", "@type": "@id" },
    "belongsToScope": { "@id": "stave:belongsToScope", "@type": "@id" },
    "hasEffectiveAccess": { "@id": "stave:hasEffectiveAccess", "@type": "@id" },
    "canImpersonate": { "@id": "stave:canImpersonate", "@type": "@id" },
    "governedBy": { "@id": "stave:governedBy", "@type": "@id" },
    "isAlgorithmShortcut": "stave:isAlgorithmShortcut",
    "severity_weight": { "@id": "stave:nodeSeverityWeight", "@type": "xsd:double" },
    "weight": { "@id": "stave:edgeSeverityWeight", "@type": "xsd:double" }
  },
  "@graph": [
`

const jsonldFooter = "\n  ]\n}\n"

// jsonldNodeEncoder is a per-export reusable encoder. The bytes.Buffer
// is reset between nodes rather than reallocated, which keeps the
// allocation count constant in the number of edges rather than nodes.
type jsonldNodeEncoder struct {
	buf bytes.Buffer
}

func newJSONLDNodeEncoder() *jsonldNodeEncoder { return &jsonldNodeEncoder{} }

// edgeGroup collects edges for a single subject and groups them by
// predicate. Multiple edges sharing a predicate become a JSON array;
// a single edge stays a scalar IRI reference.
type edgeGroup struct {
	predIRI    string
	objectIRIs []string
	edgeProps  []map[string]any
	shortcut   bool
}

func (enc *jsonldNodeEncoder) encodeNode(n *rdfNode, outgoing []rdfEdge) []byte {
	enc.buf.Reset()
	enc.buf.WriteString("    {\n      \"@id\": ")
	encodeJSONString(&enc.buf, n.ID)
	enc.buf.WriteString(",\n      \"@type\": ")
	encodeJSONString(&enc.buf, n.Type)

	// Datatype properties — emit in sorted key order so the document
	// is byte-deterministic across runs.
	if len(n.Properties) > 0 {
		keys := sortedPropKeys(n.Properties)
		for _, k := range keys {
			enc.buf.WriteString(",\n      ")
			encodeJSONString(&enc.buf, k)
			enc.buf.WriteString(": ")
			encodeJSONValue(&enc.buf, n.Properties[k])
		}
	}

	// Object properties — group by predicate, sorted predicate order.
	if len(outgoing) > 0 {
		groups := groupEdges(outgoing)
		predKeys := make([]string, 0, len(groups))
		for k := range groups {
			predKeys = append(predKeys, k)
		}
		slices.Sort(predKeys)
		for _, k := range predKeys {
			grp := groups[k]
			enc.buf.WriteString(",\n      ")
			encodeJSONString(&enc.buf, k)
			enc.buf.WriteString(": ")
			writeEdgeGroup(&enc.buf, grp)
		}
	}
	enc.buf.WriteString("\n    }")
	out := make([]byte, enc.buf.Len())
	copy(out, enc.buf.Bytes())
	return out
}

// groupEdges keys edges by their predicate IRI. Predicates appear
// in the JSON-LD document under their short context name where one
// is bound — see jsonldHeader.
func groupEdges(edges []rdfEdge) map[string]*edgeGroup {
	out := make(map[string]*edgeGroup, len(edges))
	for i := range edges {
		e := &edges[i]
		short := shortPredicate(e.Predicate)
		grp, ok := out[short]
		if !ok {
			grp = &edgeGroup{predIRI: e.Predicate}
			out[short] = grp
		}
		grp.objectIRIs = append(grp.objectIRIs, e.To)
		grp.edgeProps = append(grp.edgeProps, e.Properties)
		if e.Shortcut {
			grp.shortcut = true
		}
	}
	return out
}

// shortPredicate maps a full predicate IRI back to its short form
// declared in the @context. Falls back to the full IRI for any
// predicate not bound there.
func shortPredicate(iri string) string {
	switch iri {
	case predTargets:
		return "targets"
	case predViolatesInvariant:
		return "violatesInvariant"
	case predViolates:
		return "violates"
	case predViolatesRequirement:
		return "violatesRequirement"
	case predMapsTo:
		return "mapsTo"
	case predHasRemediation:
		return "hasRemediation"
	case predMemberOf:
		return "memberOf"
	case predProduces:
		return "produces"
	case predBelongsToScope:
		return "belongsToScope"
	case predHasEffectiveAccess:
		return "hasEffectiveAccess"
	case predCanImpersonate:
		return "canImpersonate"
	case predGovernedBy:
		return "governedBy"
	default:
		return iri
	}
}

// writeEdgeGroup emits the value of one predicate. When edge
// properties are present (e.g. weight on a shortcut edge), each
// object becomes a node-shaped reference object so the edge weight
// is preserved as RDF reification — the loss of edge attributes when
// JSON-LD flattens to triples is a documented tradeoff. Plain
// references stay scalar.
func writeEdgeGroup(buf *bytes.Buffer, grp *edgeGroup) {
	hasProps := false
	for _, p := range grp.edgeProps {
		if len(p) > 0 {
			hasProps = true
			break
		}
	}

	switch {
	case len(grp.objectIRIs) == 1 && !hasProps && !grp.shortcut:
		buf.WriteString(`{"@id": `)
		encodeJSONString(buf, grp.objectIRIs[0])
		buf.WriteString("}")
	default:
		buf.WriteString("[")
		for i, obj := range grp.objectIRIs {
			if i > 0 {
				buf.WriteString(", ")
			}
			props := grp.edgeProps[i]
			if len(props) > 0 || grp.shortcut {
				buf.WriteString("{\"@id\": ")
				encodeJSONString(buf, obj)
				if grp.shortcut {
					buf.WriteString(", \"isAlgorithmShortcut\": true")
				}
				keys := sortedPropKeys(props)
				for _, k := range keys {
					buf.WriteString(", ")
					encodeJSONString(buf, k)
					buf.WriteString(": ")
					encodeJSONValue(buf, props[k])
				}
				buf.WriteString("}")
			} else {
				buf.WriteString("{\"@id\": ")
				encodeJSONString(buf, obj)
				buf.WriteString("}")
			}
		}
		buf.WriteString("]")
	}
}

// encodeJSONString writes a JSON-quoted string. Routes through
// json.Marshal to get correct escaping for control chars, quotes,
// and Unicode without a custom escape table.
//
// json.Marshal of a Go string is not a documented failure case
// (invalid UTF-8 is replaced with U+FFFD, not errored), so the err
// branch here is theoretically unreachable. It is wired anyway so a
// future Go-runtime change cannot silently corrupt the document —
// the warning makes the regression visible and the empty-string
// fallback keeps the surrounding JSON well-formed (an `@id` or key
// that would otherwise be a bare token).
func encodeJSONString(buf *bytes.Buffer, s string) {
	b, err := json.Marshal(s)
	if err != nil {
		slog.Warn("graph jsonld: string failed to marshal; emitting empty string",
			"error", err)
		buf.WriteString(`""`)
		return
	}
	buf.Write(b)
}

// encodeJSONValue writes any JSON-encodable value into the buffer.
// Used for datatype property values where the type is map[string]any
// from upstream JSON parsing.
//
// On marshal failure the function emits `null` to keep the JSON-LD
// document well-formed — but logs a warning first so the data loss
// is visible. Earlier shape silently swallowed the marshal error,
// which made unsupported values (channels, function pointers, NaN
// floats) appear in the output as null with no signal.
func encodeJSONValue(buf *bytes.Buffer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		slog.Warn("graph jsonld: property value failed to marshal; emitting null",
			"error", err, "type", fmt.Sprintf("%T", v))
		buf.WriteString("null")
		return
	}
	buf.Write(b)
}

// sortRDF orders nodes and edges so the output is byte-deterministic
// across runs — important for golden tests and for diffing two
// exports of the same assessment.
func sortRDF(g *rdfGraph) {
	slices.SortFunc(g.Nodes, func(a, b rdfNode) int {
		return cmp.Compare(a.ID, b.ID)
	})
	slices.SortFunc(g.Edges, func(a, b rdfEdge) int {
		if a.From != b.From {
			return cmp.Compare(a.From, b.From)
		}
		if a.Predicate != b.Predicate {
			return cmp.Compare(a.Predicate, b.Predicate)
		}
		return cmp.Compare(a.To, b.To)
	})
}
