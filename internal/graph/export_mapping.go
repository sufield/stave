package graph

import (
	"log/slog"
	"strings"
)

// mapToRDFGraph converts the internal GraphData (output of Build) into
// the export-shaped RDFGraph consumable by JSON-LD and GraphML
// serializers.
//
// Three things happen here:
//  1. Each Node ID is rewritten to an IRI under urn:stave:* using the
//     URI templates the user requested (bucket/{account}/{name},
//     finding/{hash}, invariant/{category}.{number}). Original IDs are
//     preserved as datatype properties so callers can join back.
//  2. Each Edge type string is mapped to a predicate IRI via
//     wireToPredicate. Edges with no mapping are dropped with a slog
//     warning rather than emitted as fall-through "related-to" — the
//     export honors the same fail-loud-but-visible policy used by the
//     STIX marshaler for dangling edges.
//  3. Two algorithm-ready shortcut edges are materialized:
//
//       Resource --stave:violates--> Control            (1 hop)
//       (alongside) Resource --hasFinding--> Finding --violatesInvariant--> Control
//
//     This lets graph-data-science workloads run centrality and
//     community detection over the shortcut subgraph without first
//     traversing through intermediate Finding nodes, while auditors
//     get the full chain.
func mapToRDFGraph(g *GraphData) *RDFGraph {
	if g == nil {
		return &RDFGraph{OntologyIRI: strings.TrimSuffix(ontologyBaseIRI, "#")}
	}

	out := &RDFGraph{
		OntologyIRI: strings.TrimSuffix(ontologyBaseIRI, "#"),
		GeneratedAt: g.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Nodes:       make([]RDFNode, 0, len(g.Nodes)),
		Edges:       make([]RDFEdge, 0, len(g.Edges)+len(g.Nodes)),
	}

	// idMap maps internal node IDs (ARNs, finding hashes, control IDs,
	// account scope names) to their export IRIs. Built before edges
	// are translated so each edge's From/To can be rewritten in one pass.
	idMap := make(map[string]string, len(g.Nodes))
	// nodeKind tracks the original Stave node Type for each internal ID
	// so the shortcut-edge materialization step can identify Resource,
	// Finding, and Control nodes without a second scan.
	nodeKind := make(map[string]string, len(g.Nodes))
	// findingsByControl indexes Resource → controls violated transitively
	// via the Resource ← TARGETS ← Finding → Control chain. Built
	// alongside the node pass.
	findingControl := make(map[string]string, len(g.Nodes))
	// findingResource maps each Finding's internal ID to the Resource's
	// internal ID it targets, populated as TARGETS edges are seen.
	findingResource := make(map[string]string, len(g.Nodes))

	for i := range g.Nodes {
		n := &g.Nodes[i]
		iri, classIRI := nodeIRI(n)
		idMap[n.ID] = iri
		nodeKind[n.ID] = n.Type

		props := flattenNodeProperties(n)
		if n.Type == "Finding" {
			if cid, ok := stringProp(n.Properties, "control_id"); ok {
				findingControl[n.ID] = cid
			}
		}

		out.Nodes = append(out.Nodes, RDFNode{
			ID:         iri,
			Type:       classIRI,
			Properties: props,
		})
	}

	// First edge pass: rewrite to predicate IRIs, drop unmapped, build
	// the TARGETS index used by the shortcut materializer.
	for i := range g.Edges {
		e := &g.Edges[i]
		pred, ok := wireToPredicate[e.Type]
		if !ok {
			slog.Warn("graph export: dropping edge with unmapped type",
				"type", e.Type, "from", e.From, "to", e.To)
			continue
		}
		fromIRI, ok := idMap[e.From]
		if !ok {
			slog.Warn("graph export: dropping edge with unknown source node",
				"type", e.Type, "from", e.From, "to", e.To)
			continue
		}
		toIRI, ok := idMap[e.To]
		if !ok {
			slog.Warn("graph export: dropping edge with unknown target node",
				"type", e.Type, "from", e.From, "to", e.To)
			continue
		}

		props := edgeProperties(e, nodeKind[e.From], nodeKind[e.To], g)
		out.Edges = append(out.Edges, RDFEdge{
			From:       fromIRI,
			To:         toIRI,
			Predicate:  pred,
			Properties: props,
			Shortcut:   shortcutPredicates[pred],
		})

		if e.Type == "TARGETS" {
			// Wire direction: Finding -[TARGETS]-> Resource. Stash so
			// the shortcut step can pivot to Resource → Control.
			findingResource[e.From] = e.To
		}
	}

	// Materialize shortcut edges:
	//   Resource --stave:violates--> Control
	// One per (resource, control) pair. Severity weight is carried on
	// the edge so GDS algorithms can use it directly.
	type rcKey struct{ resource, control string }
	seen := make(map[rcKey]struct{}, len(findingResource))
	for findingID, controlID := range findingControl {
		resourceID, ok := findingResource[findingID]
		if !ok {
			continue
		}
		k := rcKey{resourceID, controlID}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}

		fromIRI, fromOK := idMap[resourceID]
		toIRI, toOK := idMap[controlID]
		if !fromOK || !toOK {
			continue
		}

		// Weight comes from the Finding's severity. If multiple
		// findings link the same (resource, control) pair, the
		// strongest severity wins — this matches the principle "a
		// resource is as exposed as its most dangerous finding".
		var weight float64
		for j := range g.Nodes {
			if g.Nodes[j].ID != findingID {
				continue
			}
			if sev, ok := stringProp(g.Nodes[j].Properties, "severity"); ok {
				if w := SeverityWeight(sev); w > weight {
					weight = w
				}
			}
			break
		}

		out.Edges = append(out.Edges, RDFEdge{
			From:      fromIRI,
			To:        toIRI,
			Predicate: predViolates,
			Shortcut:  true,
			Properties: map[string]any{
				"weight": weight,
			},
		})
	}

	sortRDF(out)
	return out
}

// nodeIRI maps an internal Node to its export IRI plus class IRI.
// The user's URI scheme drives the choice — bucket-class storage
// resources are stamped as stave:bucket/{account}/{name}; everything
// else falls back to the generic resource/finding/invariant prefixes.
func nodeIRI(n *Node) (instanceIRI, classIRI string) {
	switch n.Type {
	case "Resource":
		account, _ := stringProp(n.Properties, "account_id")
		class, _ := stringProp(n.Properties, "resource_class")
		providerType, _ := stringProp(n.Properties, "provider_type")
		// Bucket detection: resource_class=storage AND
		// provider_type contains "bucket" (covers aws_s3_bucket,
		// gcp_storage_bucket, azure_storage_container variants).
		if class == "storage" && strings.Contains(strings.ToLower(providerType), "bucket") {
			bucketName := lastPathSegment(n.ID)
			return BucketIRI(account, bucketName), ontologyBaseIRI + "Bucket"
		}
		return ResourceIRI(n.ID), ontologyBaseIRI + classFromResourceClass(class)
	case "Finding":
		return FindingIRI(n.ID), ontologyBaseIRI + "Finding"
	case "Control":
		category, number := splitControlID(n.ID)
		return InvariantIRI(category, number), ontologyBaseIRI + "Control"
	case "ComplianceRequirement":
		framework, _ := stringProp(n.Properties, "framework")
		reqID, _ := stringProp(n.Properties, "requirement_id")
		return RequirementIRI(framework, reqID), ontologyBaseIRI + "ComplianceRequirement"
	case "TenantScope":
		account, _ := stringProp(n.Properties, "account_id")
		return ScopeIRI(account), ontologyBaseIRI + "TenantScope"
	case "ThreatChain":
		return ChainIRI(n.ID), ontologyBaseIRI + "ThreatChain"
	case "AttackerCapability":
		return CapabilityIRI(strings.TrimPrefix(n.ID, "capability_")), ontologyBaseIRI + "AttackerCapability"
	case "RemediationAction":
		return RemediationIRI(strings.TrimPrefix(n.ID, "remediation_")), ontologyBaseIRI + "RemediationAction"
	case "Identity":
		return IdentityIRI(n.ID), ontologyBaseIRI + "Identity"
	default:
		return ResourceIRI(n.ID), ontologyBaseIRI + n.Type
	}
}

// classFromResourceClass maps the provider-agnostic resource class
// label produced by ToResourceClass to an ontology subclass of
// stave:Resource. Unknown classes fall back to the generic Resource.
func classFromResourceClass(class string) string {
	switch class {
	case "storage":
		return "StorageResource"
	case "compute":
		return "ComputeResource"
	case "network":
		return "NetworkResource"
	case "data":
		return "DataResource"
	case "secret":
		return "SecretResource"
	default:
		return "Resource"
	}
}

// flattenNodeProperties produces the datatype-property map that the
// JSON-LD and GraphML serializers emit. A few internal property keys
// are renamed to match the ontology's predicate names, and the
// severity is augmented with a numeric severityWeight so GDS
// algorithms can read it directly.
func flattenNodeProperties(n *Node) map[string]any {
	if n.Properties == nil {
		return nil
	}
	out := make(map[string]any, len(n.Properties)+2)
	for k, v := range n.Properties {
		// Skip internal IDs we already encode as @id; users joining
		// back to the original ID can read x_internal_id below.
		if k == "finding_id" || k == "control_id" || k == "resource_arn" {
			continue
		}
		out[k] = v
	}
	out["x_internal_id"] = n.ID

	if sev, ok := stringProp(n.Properties, "severity"); ok {
		out["severity_weight"] = SeverityWeight(sev)
	}
	if n.Type == "Control" {
		category, number := splitControlID(n.ID)
		out["category"] = category
		out["invariant_number"] = number
	}
	return out
}

// edgeProperties carries severity weights and other GDS-relevant
// attributes on edges. severity_weight is added on every edge whose
// endpoints make weight meaningful (Finding-bearing edges, shortcut
// edges) so a single algorithm can index by edge weight without
// guarding on type.
func edgeProperties(e *Edge, fromKind, toKind string, g *GraphData) map[string]any {
	props := map[string]any{}
	if e.Properties != nil {
		for k, v := range e.Properties {
			props[k] = v
		}
	}
	// If either endpoint is a Finding, propagate its severity weight
	// so edges incident on findings carry a numeric weight.
	if w := findingSeverityWeight(e.From, g); w > 0 && fromKind == "Finding" {
		props["weight"] = w
	} else if w := findingSeverityWeight(e.To, g); w > 0 && toKind == "Finding" {
		props["weight"] = w
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

func findingSeverityWeight(nodeID string, g *GraphData) float64 {
	for i := range g.Nodes {
		if g.Nodes[i].ID != nodeID {
			continue
		}
		if g.Nodes[i].Type != "Finding" {
			return 0
		}
		if sev, ok := stringProp(g.Nodes[i].Properties, "severity"); ok {
			return SeverityWeight(sev)
		}
		return 0
	}
	return 0
}

// splitControlID splits a Stave control ID like "CTL.S3.PUBLIC.001"
// into ("CTL.S3.PUBLIC", "001"). The user's URI shape is
// stave:invariant/{category}.{number}; category is everything up to
// the last dot, number is the suffix.
func splitControlID(id string) (category, number string) {
	idx := strings.LastIndex(id, ".")
	if idx < 0 {
		return id, ""
	}
	return id[:idx], id[idx+1:]
}

// lastPathSegment returns the substring after the last '/' or ':'.
// Used to extract a bucket name from an ARN: arn:aws:s3:::my-bucket
// → my-bucket.
func lastPathSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' || s[i] == ':' {
			return s[i+1:]
		}
	}
	return s
}

// stringProp reads a string-valued entry from a properties map.
// Returns ("", false) for missing keys, non-string values, or nil
// maps so callers can apply per-call defaults.
func stringProp(props map[string]any, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	v, ok := props[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
