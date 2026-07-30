package graph

import (
	"log/slog"
	"maps"
	"strings"

	"github.com/sufield/stave/internal/util/strutil"
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

// rdfMapper carries the indexes built during mapTordfGraph's node
// pass and consumed by the edge passes. Holding these on a struct
// lets nodePass / firstEdgePass / materializeShortcutEdges read like
// methods instead of taking 5+ parallel maps as arguments.
type rdfMapper struct {
	out *rdfGraph
	// idMap maps internal node IDs (ARNs, finding hashes, control IDs,
	// account scope names) to their export IRIs.
	idMap map[string]string
	// findingControl maps each Finding's internal ID to its
	// control_id property string.
	findingControl map[string]string
	// controlIDToNodeID maps a Finding's control_id property value to
	// the internal node ID of the Control node that should be the
	// shortcut-edge target. The two are usually identical, but the
	// previous direct idMap[controlID] lookup silently dropped the
	// shortcut edge whenever the Control node's internal ID didn't
	// match the property string verbatim.
	controlIDToNodeID map[string]string
	// findingResource maps each Finding's internal ID to the Resource's
	// internal ID it targets, populated as TARGETS edges are seen.
	findingResource map[string]string
	// nodesByID indexes nodes by their internal ID so per-edge severity
	// lookups stay O(1). The previous shape did a linear scan of g.Nodes
	// for every shortcut edge AND for every edge with a Finding endpoint,
	// turning a graph with N nodes and F findings into an O(N×F)
	// pipeline. Build the index once during the node pass.
	nodesByID map[string]*Node
}

func newRDFMapper(g *GraphData) *rdfMapper {
	return &rdfMapper{
		out: &rdfGraph{
			OntologyIRI: strings.TrimSuffix(ontologyBaseIRI, "#"),
			GeneratedAt: g.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Nodes:       make([]rdfNode, 0, len(g.Nodes)),
			Edges:       make([]rdfEdge, 0, len(g.Edges)+len(g.Nodes)),
		},
		idMap:             make(map[string]string, len(g.Nodes)),
		findingControl:    make(map[string]string, len(g.Nodes)),
		controlIDToNodeID: make(map[string]string, len(g.Nodes)),
		findingResource:   make(map[string]string, len(g.Nodes)),
		nodesByID:         make(map[string]*Node, len(g.Nodes)),
	}
}

func mapTordfGraph(g *GraphData) *rdfGraph {
	if g == nil {
		return &rdfGraph{OntologyIRI: strings.TrimSuffix(ontologyBaseIRI, "#")}
	}

	m := newRDFMapper(g)
	m.nodePass(g)
	m.firstEdgePass(g)
	m.materializeShortcutEdges()

	sortRDF(m.out)
	return m.out
}

// nodePass walks every node, emits the rdfNode, and populates
// idMap / nodesByID / findingControl / controlIDToNodeID. Routes
// classification through the IsControl / FindingControlID etc.
// discriminator methods so the raw n.Type field stays an
// implementation detail of the node type.
func (m *rdfMapper) nodePass(g *GraphData) {
	for i := range g.Nodes {
		n := &g.Nodes[i]
		iri := n.IRI()
		classIRI := n.ClassIRI()
		m.idMap[n.ID] = iri
		m.nodesByID[n.ID] = n

		props := flattenNodeProperties(n)
		if cid, ok := n.FindingControlID(); ok {
			m.findingControl[n.ID] = cid
		}
		if n.IsControl() {
			// Always map node-ID → node-ID so simple cases work even
			// when control_id isn't set as a separate property.
			m.controlIDToNodeID[n.ID] = n.ID
			if cid, ok := n.ControlPropertyID(); ok && cid != "" {
				m.controlIDToNodeID[cid] = n.ID
			}
		}

		m.out.Nodes = append(m.out.Nodes, rdfNode{
			ID:         iri,
			Type:       classIRI,
			Properties: props,
		})
	}
}

// firstEdgePass rewrites every wire edge to its predicate IRI, drops
// edges with unmapped types or unknown endpoints, and records each
// TARGETS edge into findingResource for the shortcut materializer.
func (m *rdfMapper) firstEdgePass(g *GraphData) {
	for i := range g.Edges {
		e := &g.Edges[i]
		pred, ok := e.PredicateIRI()
		if !ok {
			slog.Warn("graph export: dropping edge with unmapped type", "edge", e.DebugLabel())
			m.out.UnmappedEdges = append(m.out.UnmappedEdges, UnmappedEdge{
				Type: e.Type, From: e.From, To: e.To,
			})
			continue
		}
		fromIRI, ok := m.idMap[e.From]
		if !ok {
			slog.Warn("graph export: dropping edge with unknown source node", "edge", e.DebugLabel())
			continue
		}
		toIRI, ok := m.idMap[e.To]
		if !ok {
			slog.Warn("graph export: dropping edge with unknown target node", "edge", e.DebugLabel())
			continue
		}

		props := edgeProperties(e, m.nodesByID)
		_, isShortcut := shortcutPredicates[pred]
		m.out.Edges = append(m.out.Edges, rdfEdge{
			From:       fromIRI,
			To:         toIRI,
			Predicate:  pred,
			Properties: props,
			Shortcut:   isShortcut,
		})

		if findingID, resourceID, ok := e.FindingResourcePair(); ok {
			// Wire direction: Finding -[TARGETS]-> Resource. Stash so
			// the shortcut step can pivot to Resource → Control.
			m.findingResource[findingID] = resourceID
		}
	}
}

// materializeShortcutEdges adds Resource --stave:violates--> Control
// edges, one per (resource, control) pair. Severity weight is carried
// on the edge so GDS algorithms can use it directly.
func (m *rdfMapper) materializeShortcutEdges() {
	type rcKey struct{ resource, control string }
	seen := make(map[rcKey]struct{}, len(m.findingResource))
	for findingID, controlID := range m.findingControl {
		resourceID, ok := m.findingResource[findingID]
		if !ok {
			// Finding has a control_id but no TARGETS edge to a
			// Resource. The shortcut edge requires both endpoints,
			// so this finding contributes no Resource->Control
			// shortcut. Surface the gap instead of silently
			// skipping — typical causes: a strategy emitted a
			// finding without recording the asset link, or the
			// asset-side dedup pass dropped the edge before this
			// loop ran.
			slog.Warn("graph export: finding has control_id but no TARGETS edge; skipping shortcut",
				"finding_id", findingID, "control_id", controlID)
			continue
		}
		k := rcKey{resourceID, controlID}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}

		fromIRI, fromOK := m.idMap[resourceID]
		// Resolve control_id through the dedicated lookup before
		// hitting idMap. The previous `idMap[controlID]` lookup
		// keyed on the raw property value, which silently dropped
		// shortcut edges whenever the Control node's internal ID
		// differed from the property string.
		controlNodeID, hasControlNode := m.controlIDToNodeID[controlID]
		var toIRI string
		var toOK bool
		if hasControlNode {
			toIRI, toOK = m.idMap[controlNodeID]
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
		weight := m.nodesByID[findingID].SeverityWeight()

		m.out.Edges = append(m.out.Edges, rdfEdge{
			From:      fromIRI,
			To:        toIRI,
			Predicate: predViolates,
			Shortcut:  true,
			Properties: map[string]any{
				"weight": weight,
			},
		})
	}
}

// iriPair returns (instance IRI, class IRI) for a node. Exposed to
// the package so Node.IRI / Node.ClassIRI can share one switch
// without re-scanning Properties twice. Public callers go through
// the Node methods.
//
// The user's URI scheme drives the choice — bucket-class storage
// resources are stamped as stave:bucket/{account}/{name}; everything
// else falls back to the generic resource/finding/invariant prefixes.
func iriPair(n *Node) (instanceIRI, classIRI string) {
	if n == nil {
		return "", ""
	}
	switch n.Type {
	case NodeTypeResource:
		class := n.ResourceClass()
		// Bucket detection: resource_class=storage AND
		// provider_type contains "bucket" (covers aws_s3_bucket,
		// gcp_storage_bucket, azure_storage_container variants).
		if class == "storage" && strutil.ContainsFold(n.ProviderType(), "bucket") {
			bucketName := lastPathSegment(n.ID)
			return BucketIRI(n.AccountID(), bucketName), ontologyBaseIRI + "Bucket"
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
		return ScopeIRI(n.AccountID()), ontologyBaseIRI + "TenantScope"
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
// JSON-LD and GraphML serializers emit. The internal-ID filter +
// x_internal_id rename lives on Node.ExportProperties; this function
// layers on the ontology-flavoured derived fields (severity_weight,
// category / invariant_number for Control nodes).
func flattenNodeProperties(n *Node) map[string]any {
	out := n.ExportProperties()
	if out == nil {
		return nil
	}
	if sev, ok := n.SeverityString(); ok {
		out["severity_weight"] = SeverityWeight(sev)
	}
	if cat, num := n.ControlCategory(); cat != "" {
		out["category"] = cat
		out["invariant_number"] = num
	}
	return out
}

// edgeProperties carries severity weights and other GDS-relevant
// attributes on edges. severity_weight is added on every edge whose
// endpoints make weight meaningful (Finding-bearing edges, shortcut
// edges) so a single algorithm can index by edge weight without
// guarding on type.
//
// The previous signature took (fromKind, toKind NodeType) parameters
// duplicating what nodesByID already knows. Node.SeverityWeight() now
// returns 0 for non-Finding nodes, so the type guards collapse to the
// weight check itself.
func edgeProperties(e *Edge, nodesByID map[string]*Node) map[string]any {
	props := map[string]any{}
	if e.Properties != nil {
		maps.Copy(props, e.Properties)
	}
	// If either endpoint is a Finding, propagate its severity weight
	// so edges incident on findings carry a numeric weight.
	if w := nodesByID[e.From].SeverityWeight(); w > 0 {
		props["weight"] = w
	} else if w := nodesByID[e.To].SeverityWeight(); w > 0 {
		props["weight"] = w
	}
	if len(props) == 0 {
		return nil
	}
	return props
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
