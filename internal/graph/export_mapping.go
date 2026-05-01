package graph

import (
	"fmt"
	"log/slog"
	"maps"
	"strings"
)

// mapTordfGraph converts the internal GraphData (output of Build) into
// the export-shaped rdfGraph consumable by JSON-LD and GraphML
// serializers.
//
// Three things happen here:
//
//  1. Each Node ID is rewritten to an IRI under urn:stave:* using the
//     URI templates the user requested (bucket/{account}/{name},
//     finding/{hash}, invariant/{category}.{number}). Original IDs are
//     preserved as datatype properties so callers can join back.
//
//  2. Each Edge type string is mapped to a predicate IRI via
//     wireToPredicate. Edges with no mapping are dropped with a slog
//     warning rather than emitted as fall-through "related-to" — the
//     export honors the same fail-loud-but-visible policy used by the
//     STIX marshaler for dangling edges.
//
//  3. One algorithm-ready shortcut edge is materialized:
//
//     Resource --stave:violates--> Control            (1 hop)
//
//     The auditor path through the source graph is the inverse:
//     Finding --stave:targets--> Resource AND
//     Finding --stave:violatesRequirement--> ComplianceRequirement.
//     RDF reasoners derive Resource <- Finding via owl:inverseOf
//     on stave:targets; the explicit Resource --hasFinding--> edge
//     was redundant with the inverse and has been removed.
//
//     The shortcut lets graph-data-science workloads run centrality
//     and community detection over the shortcut subgraph without
//     first traversing through intermediate Finding nodes, while
//     auditors still get the full chain via the source edges.
//
// UnmappedEdge records an edge that was dropped during RDF mapping
// because its Type was not in the wireToPredicate vocabulary. The
// exporter previously logged these via slog.Warn only — callers had
// no programmatic way to know the export was lossy. The mapping
// surface now collects these so a caller in strict mode can fail.
type UnmappedEdge struct {
	Type EdgeType
	From string
	To   string
}

// UnmappedEdgesError is the typed error wrapping the collected
// unmapped edge list. Callers that want strict semantics check via
// errors.As; callers that don't care can ignore the error entirely
// since the bytes were still produced.
type UnmappedEdgesError struct {
	Edges []UnmappedEdge
}

// Error implements error.
func (e *UnmappedEdgesError) Error() string {
	if len(e.Edges) == 0 {
		return "no unmapped edges"
	}
	types := make(map[EdgeType]struct{}, len(e.Edges))
	for _, ue := range e.Edges {
		types[ue.Type] = struct{}{}
	}
	out := make([]string, 0, len(types))
	for t := range types {
		out = append(out, string(t))
	}
	return fmt.Sprintf("graph export dropped %d edges with unmapped type(s): %s",
		len(e.Edges), strings.Join(out, ", "))
}

func mapTordfGraph(g *GraphData) *rdfGraph {
	if g == nil {
		return &rdfGraph{OntologyIRI: strings.TrimSuffix(ontologyBaseIRI, "#")}
	}

	out := &rdfGraph{
		OntologyIRI: strings.TrimSuffix(ontologyBaseIRI, "#"),
		GeneratedAt: g.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Nodes:       make([]rdfNode, 0, len(g.Nodes)),
		Edges:       make([]rdfEdge, 0, len(g.Edges)+len(g.Nodes)),
	}

	// idMap maps internal node IDs (ARNs, finding hashes, control IDs,
	// account scope names) to their export IRIs. Built before edges
	// are translated so each edge's From/To can be rewritten in one pass.
	idMap := make(map[string]string, len(g.Nodes))
	// nodeKind tracks the original Stave node Type for each internal ID
	// so the shortcut-edge materialization step can identify Resource,
	// Finding, and Control nodes without a second scan.
	nodeKind := make(map[string]NodeType, len(g.Nodes))
	// findingsByControl indexes Resource → controls violated transitively
	// via the Resource ← TARGETS ← Finding → Control chain. Built
	// alongside the node pass.
	findingControl := make(map[string]string, len(g.Nodes))
	// controlIDToNodeID maps a Finding's control_id property value to
	// the internal node ID of the Control node that should be the
	// shortcut-edge target. The two are usually identical, but the
	// previous direct idMap[controlID] lookup silently dropped the
	// shortcut edge whenever the Control node's internal ID didn't
	// match the property string verbatim.
	controlIDToNodeID := make(map[string]string, len(g.Nodes))
	// findingResource maps each Finding's internal ID to the Resource's
	// internal ID it targets, populated as TARGETS edges are seen.
	findingResource := make(map[string]string, len(g.Nodes))
	// nodesByID indexes nodes by their internal ID so per-edge severity
	// lookups stay O(1). The previous shape did a linear scan of g.Nodes
	// for every shortcut edge AND for every edge with a Finding endpoint,
	// turning a graph with N nodes and F findings into an O(N×F)
	// pipeline. Build the index once during the node pass.
	nodesByID := make(map[string]*Node, len(g.Nodes))

	for i := range g.Nodes {
		n := &g.Nodes[i]
		iri, classIRI := nodeIRI(n)
		idMap[n.ID] = iri
		nodeKind[n.ID] = n.Type
		nodesByID[n.ID] = n

		props := flattenNodeProperties(n)
		if n.Type == NodeTypeFinding {
			if cid, ok := stringProp(n.Properties, "control_id"); ok {
				findingControl[n.ID] = cid
			}
		}
		if n.Type == NodeTypeControl {
			// Always map node-ID → node-ID so simple cases work even
			// when control_id isn't set as a separate property.
			controlIDToNodeID[n.ID] = n.ID
			if cid, ok := stringProp(n.Properties, "control_id"); ok && cid != "" {
				controlIDToNodeID[cid] = n.ID
			}
		}

		out.Nodes = append(out.Nodes, rdfNode{
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
			out.UnmappedEdges = append(out.UnmappedEdges, UnmappedEdge{
				Type: e.Type, From: e.From, To: e.To,
			})
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

		props := edgeProperties(e, nodeKind[e.From], nodeKind[e.To], nodesByID)
		out.Edges = append(out.Edges, rdfEdge{
			From:       fromIRI,
			To:         toIRI,
			Predicate:  pred,
			Properties: props,
			Shortcut:   shortcutPredicates[pred],
		})

		if e.Type == EdgeTypeTargets {
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
		// Resolve control_id through the dedicated lookup before
		// hitting idMap. The previous `idMap[controlID]` lookup
		// keyed on the raw property value, which silently dropped
		// shortcut edges whenever the Control node's internal ID
		// differed from the property string.
		controlNodeID, hasControlNode := controlIDToNodeID[controlID]
		var toIRI string
		var toOK bool
		if hasControlNode {
			toIRI, toOK = idMap[controlNodeID]
		}
		if !fromOK || !toOK {
			slog.Warn("graph export: dropping shortcut edge",
				"finding", findingID,
				"resource", resourceID,
				"control_id", controlID,
				"control_node_id", controlNodeID,
				"from_in_idmap", fromOK,
				"control_in_lookup", hasControlNode,
				"to_in_idmap", toOK)
			continue
		}

		// Weight comes from the Finding's severity. The earlier
		// shape rescanned g.Nodes per shortcut edge to handle the
		// case where multiple Finding nodes share an ID, but a graph
		// with deduplicated IDs (the contract elsewhere in this
		// package, and what builder produces) makes the loop a pure
		// O(N) tax on the O(F) shortcut pass. Use the nodesByID
		// index built during the node pass — by-ID dedup means at
		// most one Finding per ID, so a single lookup gives the
		// weight without any scan.
		var weight float64
		if n, ok := nodesByID[findingID]; ok {
			if sev, ok := stringProp(n.Properties, "severity"); ok {
				weight = SeverityWeight(sev)
			}
		}

		out.Edges = append(out.Edges, rdfEdge{
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
	case NodeTypeResource:
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
	case NodeTypeFinding:
		return FindingIRI(n.ID), ontologyBaseIRI + "Finding"
	case NodeTypeControl:
		category, number := splitControlID(n.ID)
		return InvariantIRI(category, number), ontologyBaseIRI + "Control"
	case NodeTypeComplianceRequirement:
		framework, _ := stringProp(n.Properties, "framework")
		reqID, _ := stringProp(n.Properties, "requirement_id")
		return RequirementIRI(framework, reqID), ontologyBaseIRI + "ComplianceRequirement"
	case NodeTypeTenantScope:
		account, _ := stringProp(n.Properties, "account_id")
		return ScopeIRI(account), ontologyBaseIRI + "TenantScope"
	case NodeTypeThreatChain:
		return ChainIRI(n.ID), ontologyBaseIRI + "ThreatChain"
	case NodeTypeAttackerCapability:
		return CapabilityIRI(strings.TrimPrefix(n.ID, "capability_")), ontologyBaseIRI + "AttackerCapability"
	case NodeTypeRemediationAction:
		return RemediationIRI(strings.TrimPrefix(n.ID, "remediation_")), ontologyBaseIRI + "RemediationAction"
	case NodeTypeIdentity:
		return IdentityIRI(n.ID), ontologyBaseIRI + "Identity"
	default:
		return ResourceIRI(n.ID), ontologyBaseIRI + string(n.Type)
	}
}

// classFromResourceClass maps the provider-agnostic resource class
// label produced by ToResourceClass to an ontology subclass of
// stave:Resource. Covers every class in
// docs/ontology/resource-classes.json (14 values). Unknown classes
// fall back to the generic Resource.
//
// Mapping rationale:
//   - instance, container       -> ComputeResource (workloads that run code)
//   - database, log             -> DataResource    (data-at-rest stores)
//   - identity                  -> Identity        (a separate top-level node type, not a Resource subclass)
//   - key                       -> SecretResource  (cryptographic material is a secret)
//   - cdn, dns, queue           -> NetworkResource (traffic-shaping infrastructure)
//   - registry                  -> StorageResource (artifact bytes; if the ontology grows an
//     ArtifactResource, registry should move there)
func classFromResourceClass(class string) string {
	switch class {
	case "storage":
		return "StorageResource"
	case "database":
		return "DataResource"
	case "compute":
		return "ComputeResource"
	case "instance":
		return "ComputeResource"
	case "container":
		return "ComputeResource"
	case "network":
		return "NetworkResource"
	case "identity":
		return "Identity"
	case "key":
		return "SecretResource"
	case "secret":
		return "SecretResource"
	case "cdn":
		return "NetworkResource"
	case "dns":
		return "NetworkResource"
	case "registry":
		return "StorageResource"
	case "queue":
		return "NetworkResource"
	case "log":
		return "DataResource"
	case "data":
		// Legacy / pre-14-class label. Retained for backward
		// compatibility with snapshots emitted before the taxonomy
		// expansion; new producers emit "database" or "log".
		return "DataResource"
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
	if n.Type == NodeTypeControl {
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
func edgeProperties(e *Edge, fromKind, toKind NodeType, nodesByID map[string]*Node) map[string]any {
	props := map[string]any{}
	if e.Properties != nil {
		maps.Copy(props, e.Properties)
	}
	// If either endpoint is a Finding, propagate its severity weight
	// so edges incident on findings carry a numeric weight.
	if w := findingSeverityWeight(e.From, nodesByID); w > 0 && fromKind == NodeTypeFinding {
		props["weight"] = w
	} else if w := findingSeverityWeight(e.To, nodesByID); w > 0 && toKind == NodeTypeFinding {
		props["weight"] = w
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

// findingSeverityWeight returns the SeverityWeight of the Finding
// node with the given ID, or 0 if the node isn't a Finding or has no
// severity property. The previous signature accepted *GraphData and
// scanned its Nodes slice on every call, making per-edge work O(N).
// Switching to the prebuilt index keeps the hot path O(1).
func findingSeverityWeight(nodeID string, nodesByID map[string]*Node) float64 {
	n, ok := nodesByID[nodeID]
	if !ok || n.Type != NodeTypeFinding {
		return 0
	}
	if sev, ok := stringProp(n.Properties, "severity"); ok {
		return SeverityWeight(sev)
	}
	return 0
}

// splitControlID splits a Stave control ID like "CTL.S3.PUBLIC.001"
// into ("CTL.S3.PUBLIC", "001"). The user's URI shape is
// stave:invariant/{category}.{number}; category is everything up to
// the last dot, number is the suffix.
//
// A dot-free control ID is a data-quality issue (custom or
// malformed input) — log a warning so operators can find and fix
// the source, and use the whole ID as the *number* with category
// "default". InvariantIRI renders the result as `category.number`,
// so an empty number would produce a trailing-dot IRI like
// `urn:stave:invariant/CTRL001.`, which downstream RDF parsers
// reject; using "default" as the category keeps the IRI well-formed
// AND surfaces the data issue in a recognizable way.
func splitControlID(id string) (category, number string) {
	idx := strings.LastIndex(id, ".")
	if idx < 0 {
		slog.Warn("graph export: control ID has no dot separator; using 'default' category",
			"control_id", id)
		return "default", id
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
