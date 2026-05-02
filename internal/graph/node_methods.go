package graph

import (
	"fmt"
	"time"
)

// Tell-don't-ask methods on Node and Edge. Callers used to read
// (n.Type, n.Properties[...]) tuples and reproduce the same per-type
// switches every place a node touched the wire format. Centralising
// the "what is my IRI? what is my STIX object? what is my severity?"
// answers on the type that owns the data lets export_mapping.go and
// marshal_stix.go stop reaching into the property bag.

// FindingControlID returns the control_id property of a Finding node.
// Returns "", false for any non-Finding node or when the property is
// missing — callers no longer guard on n.Type == NodeTypeFinding
// before reading the property.
func (n *Node) FindingControlID() (string, bool) {
	if n == nil || n.Type != NodeTypeFinding {
		return "", false
	}
	return stringProp(n.Properties, "control_id")
}

// ControlCategory returns the (category, number) split of a Control
// node's ID — e.g. "CTL.S3.PUBLIC.001" → ("CTL.S3.PUBLIC", "001"). For
// any non-Control node both returns are "". The previous shape exposed
// splitControlID at the package level and required every caller to
// gate on n.Type == NodeTypeControl first.
func (n *Node) ControlCategory() (category, number string) {
	if n == nil || n.Type != NodeTypeControl {
		return "", ""
	}
	return splitControlID(n.ID)
}

// SeverityWeight returns the numeric severity weight for Finding
// nodes. Returns 0 for any other node type or for a Finding without
// a "severity" property. Subsumes the package-level
// findingSeverityWeight helper plus its (n.Type != NodeTypeFinding)
// guard so callers can ask any node for its weight without a type
// check; non-Finding nodes simply contribute 0.
func (n *Node) SeverityWeight() float64 {
	if n == nil || n.Type != NodeTypeFinding {
		return 0
	}
	sev, ok := stringProp(n.Properties, "severity")
	if !ok {
		return 0
	}
	return SeverityWeight(sev)
}

// SeverityString returns the raw severity string from the node's
// property bag, or "" when missing. Lets flattenNodeProperties stop
// reaching directly into n.Properties — callers ask the node for
// its severity string and the package-level stringProp helper stays
// internal.
func (n *Node) SeverityString() (string, bool) {
	if n == nil {
		return "", false
	}
	return stringProp(n.Properties, "severity")
}

// IsControl reports whether this node represents a Control node
// (in the closed NodeType vocabulary). Replaces the
// (n.Type == NodeTypeControl) probe in the rdf-mapping node pass.
func (n *Node) IsControl() bool {
	return n != nil && n.Type == NodeTypeControl
}

// ControlPropertyID returns the control_id property string, or
// ("", false) when the node has no such property. Encapsulates the
// stringProp(n.Properties, "control_id") probe used in the
// nodePass / shortcut-edge materialiser so the property-bag key
// stays internal to the type.
func (n *Node) ControlPropertyID() (string, bool) {
	if n == nil {
		return "", false
	}
	return stringProp(n.Properties, "control_id")
}

// IRI returns the export instance IRI for this node. The class IRI
// is exposed separately as ClassIRI; the previous package-level
// nodeIRI helper returned both as a tuple, which forced the rdfMapper
// to keep the type-switch logic at the top of nodePass instead of
// asking the node directly.
func (n *Node) IRI() string {
	iri, _ := iriPair(n)
	return iri
}

// ClassIRI returns the ontology class IRI for this node (e.g.
// stave:Bucket, stave:Finding, stave:Control). See IRI for the
// instance IRI.
func (n *Node) ClassIRI() string {
	_, class := iriPair(n)
	return class
}

// STIXObject returns the STIX 2.1 SDO representation for this node.
// The producerID is the Stave producer Identity SDO that becomes the
// created_by_ref. The returned (id, obj) pair is fully populated:
// callers no longer maintain the per-node-type switch for
// type-specific properties (first_observed, infrastructure_types,
// kill_chain_phases, etc.) — those decisions belong to the node.
//
// nil receiver returns ("", nil) so the caller can decide whether to
// skip or surface a producer-side bug.
func (n *Node) STIXObject(now time.Time, producerID string) (string, map[string]any) {
	if n == nil {
		return "", nil
	}
	stixType := stixObjectTypeMap[n.Type]
	if stixType == "" {
		stixType = "x-stave-" + string(n.Type)
	}
	sid := stixID(stixType, n.ID)
	nowStr := now.Format(time.RFC3339)
	obj := map[string]any{
		"type":           stixType,
		"id":             sid,
		"spec_version":   "2.1",
		"created":        nowStr,
		"modified":       nowStr,
		"created_by_ref": producerID,
	}

	switch n.Type {
	case NodeTypeFinding:
		obj["first_observed"] = nowStr
		obj["last_observed"] = nowStr
		obj["number_observed"] = 1
		obj["extensions"] = map[string]any{
			"x_stave_finding": n.Properties,
		}
	case NodeTypeResource:
		obj["name"] = n.ID
		if rc, ok := n.Properties["resource_class"].(string); ok {
			obj["infrastructure_types"] = []string{rc}
		}
	case NodeTypeThreatChain:
		obj["name"] = n.ID
		if desc, ok := n.Properties["narrative"]; ok {
			obj["description"] = desc
		}
		if phases, ok := n.Properties["kill_chain_phases"]; ok {
			obj["kill_chain_phases"] = phases
		}
	case NodeTypeAttackerCapability:
		obj["name"] = "Capability: " + n.ID
		if desc, ok := n.Properties["compound_severity"]; ok {
			obj["description"] = fmt.Sprintf("Chain capability — severity: %s", desc)
		}
	case NodeTypeControl, NodeTypeComplianceRequirement, NodeTypeRemediationAction:
		switch {
		case stringPropPresent(n.Properties, "control_name"):
			obj["name"], _ = stringProp(n.Properties, "control_name")
		case stringPropPresent(n.Properties, "action"):
			obj["name"], _ = stringProp(n.Properties, "action")
		default:
			obj["name"] = n.ID
		}
		if desc, ok := stringProp(n.Properties, "control_id"); ok {
			obj["description"] = desc
		}
	case NodeTypeTenantScope:
		obj["name"] = "Account " + n.ID
		obj["identity_class"] = "organization"
	case NodeTypeIdentity:
		obj["name"] = n.ID
		obj["identity_class"] = "system"
	}

	return sid, obj
}

// stringPropPresent reports whether props[key] is a non-empty string.
// Used by STIXObject's name-fallback chain so it doesn't have to do
// the (assert string + non-empty) dance inline three times.
func stringPropPresent(props map[string]any, key string) bool {
	s, ok := stringProp(props, key)
	return ok && s != ""
}

// IsTargets reports whether this edge is a Finding -[TARGETS]-> Resource
// edge. Used by the RDF mapper to pivot from finding-side TARGETS edges
// to the (resource, control) shortcut edges. Replaces the
// (e.Type == EdgeTypeTargets) field probe at the call site so future
// edge-type renames touch one place.
func (e *Edge) IsTargets() bool {
	return e != nil && e.Type == EdgeTypeTargets
}

// PredicateIRI returns the RDF predicate IRI this edge maps to in
// the JSON-LD / GraphML export, or ("", false) when the edge type is
// not in the wireToPredicate vocabulary. Encapsulates the package-
// level wireToPredicate lookup at the call site (firstEdgePass) so
// callers ask the edge for its predicate rather than indexing into
// a private map.
func (e *Edge) PredicateIRI() (string, bool) {
	if e == nil {
		return "", false
	}
	pred, ok := wireToPredicate[e.Type]
	return pred, ok
}

// FindingResourcePair returns the (finding, resource) endpoints when
// this edge is a TARGETS edge, or ("", "", false) otherwise. Callers
// that previously read (e.Type == EdgeTypeTargets, e.From, e.To)
// collapse to a single method call.
func (e *Edge) FindingResourcePair() (finding, resource string, ok bool) {
	if !e.IsTargets() {
		return "", "", false
	}
	return e.From, e.To, true
}
