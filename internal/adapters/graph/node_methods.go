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

// ResourceClass / AccountID / ProviderType / ControlName / Narrative
// are typed accessors over Properties[<key>]. They centralise the
// stringProp(n.Properties, "<key>") lookups that the export and STIX
// pipelines used to perform inline so a future property-key rename
// is one edit on the type. nil receiver and missing keys return "".

// ResourceClass returns the asset's "resource_class" property
// (e.g. "storage", "identity", "compute"), or "" when missing.
func (n *Node) ResourceClass() string {
	s, _ := stringProp(propertiesOf(n), "resource_class")
	return s
}

// AccountID returns the cloud account identifier the node is
// scoped to. Used by the IRI builder for Resource and TenantScope
// nodes.
func (n *Node) AccountID() string {
	s, _ := stringProp(propertiesOf(n), "account_id")
	return s
}

// ProviderType returns the snapshot provider's resource type
// string (e.g. "aws_s3_bucket", "gcp_storage_bucket"). Used by
// iriPair's bucket-detection branch.
func (n *Node) ProviderType() string {
	s, _ := stringProp(propertiesOf(n), "provider_type")
	return s
}

// ControlName returns the human-readable name attached to a
// Control / ComplianceRequirement / RemediationAction node. Used
// by STIXObject when picking the SDO display name.
func (n *Node) ControlName() string {
	s, _ := stringProp(propertiesOf(n), "control_name")
	return s
}

// Narrative returns the "narrative" property as the raw any
// value. ThreatChain / AttackerCapability use it as the STIX
// description; the field is not always a string so it is returned
// as-is.
func (n *Node) Narrative() any {
	if n == nil || n.Properties == nil {
		return nil
	}
	return n.Properties["narrative"]
}

// propertiesOf safely returns the Properties map of n, or nil for a
// nil receiver. Internal helper for the typed accessors above.
func propertiesOf(n *Node) map[string]any {
	if n == nil {
		return nil
	}
	return n.Properties
}

// ExportProperties returns a copy of the node's Properties map with
// internal ID keys (finding_id, control_id, resource_arn) filtered
// out and an x_internal_id entry added. Centralises the flatten
// step so flattenNodeProperties stops poking individual keys at the
// call site.
func (n *Node) ExportProperties() map[string]any {
	if n == nil || n.Properties == nil {
		return nil
	}
	out := make(map[string]any, len(n.Properties)+1)
	for k, v := range n.Properties {
		switch k {
		case "finding_id", "control_id", "resource_arn":
			continue
		}
		out[k] = v
	}
	out["x_internal_id"] = n.ID
	return out
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
		if rc := n.ResourceClass(); rc != "" {
			obj["infrastructure_types"] = []string{rc}
		}
	case NodeTypeThreatChain:
		obj["name"] = n.ID
		if desc := n.Narrative(); desc != nil {
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
		case n.ControlName() != "":
			obj["name"] = n.ControlName()
		case stringPropPresent(n.Properties, "action"):
			obj["name"], _ = stringProp(n.Properties, "action")
		default:
			obj["name"] = n.ID
		}
		if desc, ok := n.ControlPropertyID(); ok {
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

// IsShortcut reports whether this export edge was materialised as an
// algorithmic shortcut (Resource → Control "violates" edges synthesised
// from finding chains) rather than coming from the original graph.
// Replaces the bare e.Shortcut field probe in the GraphML exporter so
// the answer lives on the type that owns the field.
func (e *rdfEdge) IsShortcut() bool {
	return e != nil && e.Shortcut
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
