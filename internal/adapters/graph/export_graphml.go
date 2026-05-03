package graph

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// MarshalGraphML writes a GraphML XML document for the graph. GraphML
// is the native exchange format for igraph, NetworkX, Gephi, yEd,
// and Cytoscape — every one of them imports it without conversion.
//
// Stave's GraphML output:
//   - declares typed <key> attributes for every node / edge property
//     that appears in the graph (severity, severity_weight, category,
//     account_id, isAlgorithmShortcut, ...) so consumers know the
//     data type without inferring;
//   - encodes severity and weight as numeric (xsd:double) so GDS
//     algorithms can read them as edge weights / partition keys
//     without re-parsing strings;
//   - flags shortcut edges with a boolean isAlgorithmShortcut
//     attribute so a community-detection run can ignore them or
//     filter to them as needed.
//
// Streamed via *bufio.Writer with a single bytes.Buffer reused for
// per-element XML escaping. Allocations scale with the largest single
// element, not with the whole graph.
func MarshalGraphML(w io.Writer, g *GraphData) error {
	_, err := MarshalGraphMLWithDiagnostics(w, g)
	return err
}

// MarshalGraphMLWithDiagnostics is the same as MarshalGraphML but
// also returns the list of unmapped-type edges. See
// MarshalJSONLDWithDiagnostics for the contract.
func MarshalGraphMLWithDiagnostics(w io.Writer, g *GraphData) ([]UnmappedEdge, error) {
	if g == nil {
		return nil, errors.New("MarshalGraphML: nil GraphData")
	}
	rdf := mapTordfGraph(g)

	keys := collectGraphMLKeys(rdf)
	// Build the key index once. The previous implementation rebuilt
	// the same map inside every writeGraphMLNode and
	// writeGraphMLEdge call, allocating O(nodes+edges) identical
	// maps for no gain.
	idx := indexKeys(keys)

	xw := &graphmlWriter{w: bufio.NewWriter(w)}
	xw.writeString(xml.Header)
	xw.writeString(graphmlOpen)

	// Key declarations come first per GraphML spec: schema before data.
	for _, k := range keys {
		xw.writeString(keyElement(k))
	}
	xw.writeString(graphmlGraphOpen)

	scratch := &bytes.Buffer{}

	for i := range rdf.Nodes {
		writeGraphMLNode(xw, scratch, &rdf.Nodes[i], idx)
	}
	for i := range rdf.Edges {
		writeGraphMLEdge(xw, scratch, &rdf.Edges[i], idx, i)
	}

	xw.writeString(graphmlClose)
	if xw.err != nil {
		return rdf.UnmappedEdges, xw.err
	}
	return rdf.UnmappedEdges, xw.w.Flush()
}

// graphmlWriter wraps a *bufio.Writer with a sticky first error so each
// per-element write site stays a single statement. Keeping the error on
// the wrapper lets MarshalGraphML check once at the end without every
// Write/WriteString call site polluting the output with `if _, err :=`
// boilerplate that errcheck legitimately flags as discarded errors.
type graphmlWriter struct {
	w   *bufio.Writer
	err error
}

func (x *graphmlWriter) writeString(s string) {
	if x.err != nil {
		return
	}
	if _, err := x.w.WriteString(s); err != nil {
		x.err = err
	}
}

func (x *graphmlWriter) write(b []byte) {
	if x.err != nil {
		return
	}
	if _, err := x.w.Write(b); err != nil {
		x.err = err
	}
}

const graphmlOpen = `<graphml xmlns="http://graphml.graphdrawing.org/xmlns"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.1/graphml.xsd">
`

const graphmlGraphOpen = `<graph id="stave" edgedefault="directed">
`

const graphmlClose = `</graph>
</graphml>
`

// graphmlKey describes one declared <key> in the document. for is
// "node" or "edge"; attrType is one of "string", "double", "int",
// "boolean" — the GraphML-recognized types.
type graphmlKey struct {
	id       string
	for_     string
	name     string
	attrType string
}

// collectGraphMLKeys builds the set of <key> declarations needed for
// the document. It walks every node and edge once, infers the
// attribute type from the value's Go type, and returns a sorted slice
// keyed by (for, name) so GraphML imports are deterministic.
func collectGraphMLKeys(rdf *rdfGraph) []graphmlKey {
	type seenKey struct{ for_, name string }
	seen := make(map[seenKey]graphmlKey)

	add := func(forVal, name, attrType string) {
		k := seenKey{forVal, name}
		if existing, ok := seen[k]; ok {
			// GraphML <key> declarations are document-global: every row
			// for the same (for, name) must share one type. Promote to
			// the most-permissive type that covers both — int → double
			// → string, with boolean joining either side as string —
			// instead of letting whichever row was visited last decide.
			attrType = promoteAttrType(existing.attrType, attrType)
			if attrType == existing.attrType {
				return
			}
		}
		seen[k] = graphmlKey{id: forVal[:1] + "_" + name, for_: forVal, name: name, attrType: attrType}
	}

	// Always declared so every node carries its @type and every edge
	// its predicate label, regardless of which property keys the
	// individual instances happen to populate.
	add("node", "type", "string")
	add("edge", "label", "string")
	add("edge", "isAlgorithmShortcut", "boolean")

	for i := range rdf.Nodes {
		for k, v := range rdf.Nodes[i].Properties {
			add("node", k, inferAttrType(v))
		}
	}
	for i := range rdf.Edges {
		for k, v := range rdf.Edges[i].Properties {
			add("edge", k, inferAttrType(v))
		}
	}

	out := make([]graphmlKey, 0, len(seen))
	for _, k := range seen {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].for_ != out[j].for_ {
			return out[i].for_ < out[j].for_
		}
		return out[i].name < out[j].name
	})
	// Re-id once positions are stable so id values are deterministic.
	for i := range out {
		out[i].id = out[i].for_[:1] + "_" + out[i].name
	}
	return out
}

// inferAttrType maps a Go runtime value to a GraphML attribute type.
// Numeric types collapse to double (the most permissive numeric);
// strings stay strings; bools stay bools; anything else is a string
// since GraphML cannot represent structured values inline.
func inferAttrType(v any) string {
	switch v.(type) {
	case bool:
		return "boolean"
	case int, int32, int64:
		return "int"
	case float32, float64:
		return "double"
	case string:
		return "string"
	default:
		return "string"
	}
}

// promoteAttrType picks the GraphML attribute type that covers both
// operands when two rows disagree. Same type → unchanged. Compatible
// numeric pair (int/double) → double. Anything else → string, the
// universal fallback that the GraphML reader can always parse.
func promoteAttrType(a, b string) string {
	if a == b {
		return a
	}
	if (a == "int" && b == "double") || (a == "double" && b == "int") {
		return "double"
	}
	return "string"
}

func keyElement(k graphmlKey) string {
	return fmt.Sprintf("  <key id=\"%s\" for=\"%s\" attr.name=\"%s\" attr.type=\"%s\"/>\n",
		xmlEscape(k.id), xmlEscape(k.for_), xmlEscape(k.name), xmlEscape(k.attrType))
}

// keyIndex maps (for, name) → key id. Built once per export, used
// while emitting <data> elements so each property reference resolves
// in O(1).
type keyIndex map[string]string

func indexKeys(keys []graphmlKey) keyIndex {
	out := make(keyIndex, len(keys))
	for _, k := range keys {
		out[k.for_+":"+k.name] = k.id
	}
	return out
}

func writeGraphMLNode(xw *graphmlWriter, scratch *bytes.Buffer, n *rdfNode, idx keyIndex) {
	xw.writeString("  <node id=\"")
	xw.writeString(xmlEscape(n.ID))
	xw.writeString("\">\n")

	if id, ok := idx["node:type"]; ok {
		xw.writeString("    <data key=\"")
		xw.writeString(id)
		xw.writeString("\">")
		xw.writeString(xmlEscape(n.Type))
		xw.writeString("</data>\n")
	}

	for _, k := range sortedPropKeys(n.Properties) {
		id, ok := idx["node:"+k]
		if !ok {
			continue
		}
		writeGraphMLData(xw, scratch, id, n.Properties[k])
	}
	xw.writeString("  </node>\n")
}

func writeGraphMLEdge(xw *graphmlWriter, scratch *bytes.Buffer, e *rdfEdge, keyIdx keyIndex, idx int) {
	xw.writeString("  <edge id=\"e")
	xw.writeString(strconv.Itoa(idx))
	xw.writeString("\" source=\"")
	xw.writeString(xmlEscape(e.From))
	xw.writeString("\" target=\"")
	xw.writeString(xmlEscape(e.To))
	xw.writeString("\">\n")

	// Edge label — short predicate name so consumers reading the
	// GraphML in Gephi or Cytoscape see "violates" rather than the
	// full IRI on edge labels.
	if id, ok := keyIdx["edge:label"]; ok {
		xw.writeString("    <data key=\"")
		xw.writeString(id)
		xw.writeString("\">")
		xw.writeString(xmlEscape(shortPredicate(e.Predicate)))
		xw.writeString("</data>\n")
	}

	if e.IsShortcut() {
		if id, ok := keyIdx["edge:isAlgorithmShortcut"]; ok {
			xw.writeString("    <data key=\"")
			xw.writeString(id)
			xw.writeString("\">true</data>\n")
		}
	}

	for _, k := range sortedPropKeys(e.Properties) {
		id, ok := keyIdx["edge:"+k]
		if !ok {
			continue
		}
		writeGraphMLData(xw, scratch, id, e.Properties[k])
	}
	xw.writeString("  </edge>\n")
}

// writeGraphMLData emits one <data key="..."> element with a value
// rendered to its GraphML lexical form. Numeric values use the
// canonical Go formatting which produces XSD-compliant double
// representations; bools produce "true"/"false"; strings are XML-
// escaped via xmlEscape.
func writeGraphMLData(xw *graphmlWriter, scratch *bytes.Buffer, keyID string, v any) {
	xw.writeString("    <data key=\"")
	xw.writeString(keyID)
	xw.writeString("\">")
	scratch.Reset()
	switch val := v.(type) {
	case nil:
		// Empty data element.
	case bool:
		if val {
			scratch.WriteString("true")
		} else {
			scratch.WriteString("false")
		}
	case int:
		scratch.WriteString(strconv.Itoa(val))
	case int32:
		scratch.WriteString(strconv.FormatInt(int64(val), 10))
	case int64:
		scratch.WriteString(strconv.FormatInt(val, 10))
	case float32:
		scratch.WriteString(strconv.FormatFloat(float64(val), 'g', -1, 32))
	case float64:
		scratch.WriteString(strconv.FormatFloat(val, 'g', -1, 64))
	case string:
		scratch.WriteString(xmlEscape(val))
	default:
		// Fall back to JSON-encoded string for any structured value
		// — GraphML doesn't natively represent maps or arrays.
		scratch.WriteString(xmlEscape(fmt.Sprintf("%v", v)))
	}
	xw.write(scratch.Bytes())
	xw.writeString("</data>\n")
}

// xmlEscape XML-escapes the five reserved characters. Hand-rolled
// rather than xml.EscapeString because EscapeString allocates a new
// string for every call; the scratch buffer in the streaming writer
// would otherwise see one allocation per <data> element.
func xmlEscape(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '&' || c == '<' || c == '>' || c == '"' || c == '\'' {
			return xmlEscapeSlow(s)
		}
	}
	return s
}

func xmlEscapeSlow(s string) string {
	var b bytes.Buffer
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
