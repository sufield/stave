package graph

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/attack"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
	"github.com/sufield/stave/internal/util/sets"
)

// GraphData is the top-level graph-json output.
type GraphData struct {
	SchemaVersion   string        `json:"schema_version"`
	OntologyVersion string        `json:"ontology_version"`
	GeneratedAt     time.Time     `json:"generated_at"`
	Source          GraphSource   `json:"source"`
	Nodes           []Node        `json:"nodes"`
	Edges           []Edge        `json:"edges"`
	Metadata        GraphMetadata `json:"metadata"`
}

// GraphSource records what inputs produced this graph.
type GraphSource struct {
	AssessmentOutput string `json:"assessment_output"`
	Snapshot         string `json:"snapshot,omitempty"`
	IdentityLayer    bool   `json:"identity_layer"`
}

// GraphMetadata provides summary counts for validation.
type GraphMetadata struct {
	NodeCount int              `json:"node_count"`
	EdgeCount int              `json:"edge_count"`
	NodeTypes map[NodeType]int `json:"node_types"`
	EdgeTypes map[EdgeType]int `json:"edge_types"`
}

// NodeType names the closed vocabulary of graph node kinds. Centralizing
// the set makes the (n.Type == "Finding") string comparisons typed and
// turns up typos at compile time. Values are the on-the-wire JSON
// strings the graph emits.
type NodeType string

// Recognized node types. The graph builder constructs nodes only from
// this list; readers (export_mapping.go, etc.) compare against these
// constants instead of open-coded literals.
const (
	NodeTypeFinding               NodeType = "Finding"
	NodeTypeResource              NodeType = "Resource"
	NodeTypeControl               NodeType = "Control"
	NodeTypeComplianceRequirement NodeType = "ComplianceRequirement"
	NodeTypeTenantScope           NodeType = "TenantScope"
	NodeTypeRemediationAction     NodeType = "RemediationAction"
	NodeTypeThreatChain           NodeType = "ThreatChain"
	NodeTypeAttackerCapability    NodeType = "AttackerCapability"
	// NodeTypeIdentity covers IAM principals (roles, users, service
	// accounts) when the graph carries the identity layer. Surfaced
	// as a STIX 2.1 Identity SDO in the STIX export and as
	// stave:Identity in JSON-LD.
	NodeTypeIdentity NodeType = "Identity"
)

// EdgeType names the closed vocabulary of graph edge kinds. Same
// rationale as NodeType.
type EdgeType string

const (
	EdgeTypeTargets        EdgeType = "TARGETS"
	EdgeTypeMapsTo         EdgeType = "MAPS_TO"
	EdgeTypeBelongsToScope EdgeType = "BELONGS_TO_SCOPE"
	EdgeTypeHasRemediation EdgeType = "HAS_REMEDIATION"
	EdgeTypeMemberOf       EdgeType = "MEMBER_OF"
	EdgeTypeProduces       EdgeType = "PRODUCES"

	// EdgeTypeViolatesRequirement is the Finding -> ComplianceRequirement
	// edge mapped to the ontology predicate stave:violatesRequirement.
	// Wire string VIOLATES_REQUIREMENT keeps it distinct from the
	// generic VIOLATES used by the synthesized Resource->Control
	// shortcut, so RDF consumers can filter the two without parsing
	// edge endpoints.
	EdgeTypeViolatesRequirement EdgeType = "VIOLATES_REQUIREMENT"

	// EdgeTypeViolates is retained as a legacy alias for the same
	// Finding -> ComplianceRequirement edge. Older producers emitted
	// VIOLATES; the export layer maps both wire strings to the
	// stave:violatesRequirement predicate. New code should use
	// EdgeTypeViolatesRequirement for clarity.
	EdgeTypeViolates EdgeType = "VIOLATES"

	// EdgeTypeViolatesInvariant is the Finding -> Control edge:
	// "this finding asserts the control's invariant was false on
	// this asset at this time". Distinct from ViolatesRequirement,
	// which connects the finding to the compliance requirement the
	// control claims to cover.
	EdgeTypeViolatesInvariant EdgeType = "VIOLATES_INVARIANT"

	// Identity-layer edges. Used when the graph carries IAM
	// principals as Identity nodes alongside Resource nodes.
	EdgeTypeHasEffectiveAccess EdgeType = "HAS_EFFECTIVE_ACCESS"
	EdgeTypeCanImpersonate     EdgeType = "CAN_IMPERSONATE"
	EdgeTypeGovernedBy         EdgeType = "GOVERNED_BY"
)

// Node is a graph node with typed properties.
type Node struct {
	ID           string         `json:"id"`
	Type         NodeType       `json:"type"`
	Standard     string         `json:"standard"`
	StandardType string         `json:"standard_type"`
	Properties   map[string]any `json:"properties"`
}

// Edge is a graph edge with optional properties.
type Edge struct {
	From       string         `json:"from"`
	To         string         `json:"to"`
	Type       EdgeType       `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
}

// DebugLabel returns a single-string label suitable for slog
// "graph export: dropping edge ..." warnings. Centralised so the
// drop-warning sites stop spelling out (type, from, to) at every
// log call — a future field rename or telemetry-redaction tweak
// is one edit on the type.
func (e *Edge) DebugLabel() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s %s -> %s", e.Type, e.From, e.To)
}

// BuildInput holds the data for graph construction.
type BuildInput struct {
	Findings      []remediation.Finding
	ChainFindings []risk.CompoundFinding
	Now           time.Time
	SourcePath    string
}

// builderState carries the dedup sets and graph reference threaded
// through Build's per-finding and per-chain helpers. Holding these on
// a single value lets the helpers read like ordinary methods instead
// of accepting a long parameter list, while keeping all dedup state
// scoped to one Build() invocation.
type builderState struct {
	g                *GraphData
	seenNodes        sets.Set[string]
	seenRequirements sets.Set[string]
	seenAccounts     sets.Set[string]
	seenMapsTo       sets.Set[string]
	seenBelongsTo    sets.Set[string]
	seenViolates     sets.Set[string]
}

func newBuilderState(g *GraphData) *builderState {
	return &builderState{
		g:                g,
		seenNodes:        sets.New[string](),
		seenRequirements: sets.New[string](),
		seenAccounts:     sets.New[string](),
		// seenMapsTo / seenBelongsTo / seenViolates: inline edge-dedup
		// sets so the post-pass deduplicateEdges doesn't have to walk a
		// duplicate-laden slice on the hot path. Each tracks
		// (from→to) pairs for the corresponding edge type — see Build()
		// for the rationale of each.
		seenMapsTo:    sets.New[string](),
		seenBelongsTo: sets.New[string](),
		seenViolates:  sets.New[string](),
	}
}

// emitOnce appends node to g.Nodes the first time id is seen and
// records the id in seenNodes. Replaces the eight-times-repeated
// `if !seen.Contains(id) { seen.Add(id); append(...) }` block — the
// node-emission pattern needs a single source of truth so the dedup
// invariant is impossible to forget at a new call site.
func (b *builderState) emitOnce(id string, node Node) {
	if b.seenNodes.Contains(id) {
		return
	}
	b.seenNodes.Add(id)
	b.g.Nodes = append(b.g.Nodes, node)
}

// Build constructs a GraphData from assessment output.
func Build(input BuildInput) *GraphData {
	g := &GraphData{
		SchemaVersion:   "1",
		OntologyVersion: metadata.OntologyVersion,
		GeneratedAt:     input.Now,
		Source: GraphSource{
			AssessmentOutput: input.SourcePath,
		},
	}
	b := newBuilderState(g)

	// Findings → Finding nodes, Resource nodes, Control nodes,
	// ComplianceRequirement nodes, TenantScope nodes, and edges.
	for i := range input.Findings {
		b.processFinding(&input.Findings[i])
	}

	// Build a single index of findings keyed by control ID before
	// the chain loop. The previous nested-scan approach was O(N×M)
	// where N = ChainFindings × ControlsFailing and M = total
	// findings; on a 200-finding bundle with 20 chains that's ~4k
	// inner iterations per outer pass, all of which fed
	// deduplicateEdges with redundant copies anyway.
	findingsByControl := buildFindingsByControlIndex(input.Findings)

	// ChainFindings → ThreatChain + AttackerCapability nodes and edges.
	for i := range input.ChainFindings {
		b.processChainFinding(&input.ChainFindings[i], findingsByControl, input.Findings)
	}

	// Deduplicate edges.
	g.Edges = deduplicateEdges(g.Edges)

	// Compute metadata.
	g.Metadata = computeMetadata(g.Nodes, g.Edges)

	return g
}

// buildFindingsByControlIndex groups finding indexes by ControlID for
// O(1) lookup during the chain-finding loop.
func buildFindingsByControlIndex(findings []remediation.Finding) map[kernel.ControlID][]int {
	idx := make(map[kernel.ControlID][]int, len(findings))
	for j := range findings {
		ff := &findings[j]
		idx[ff.ControlID] = append(idx[ff.ControlID], j)
	}
	return idx
}

// processFinding emits the Finding/Resource/Control/Compliance/
// TenantScope/Remediation nodes and edges for a single finding.
func (b *builderState) processFinding(f *remediation.Finding) {
	// Finding node. The graph layer uses untyped string IDs
	// (Node.ID, Edge.From/To) since they mix finding, asset,
	// chain, and control IDs in the same field. Cast at the
	// boundary so the rest of this builder stays string-only.
	findingID := string(f.FindingID)
	b.emitOnce(findingID, Node{
		ID: findingID, Type: NodeTypeFinding,
		Standard: "ocsf", StandardType: "Security Finding (2001)",
		Properties: buildFindingProperties(f),
	})

	// Resource node.
	resourceID := string(f.AssetID)
	providerType := string(f.AssetType)
	b.emitOnce(resourceID, Node{
		ID: resourceID, Type: NodeTypeResource,
		Standard: "ocsf", StandardType: "Infrastructure",
		Properties: map[string]any{
			"resource_arn":   resourceID,
			"resource_class": ToResourceClass(providerType),
			"provider":       string(f.AssetVendor),
			"provider_type":  providerType,
			"account_id":     extractAccountID(resourceID),
		},
	})

	// TARGETS edge.
	b.g.Edges = append(b.g.Edges, Edge{
		From: findingID, To: resourceID, Type: EdgeTypeTargets,
	})

	b.emitControlNode(f)
	b.emitComplianceEdges(f, findingID)
	b.emitTenantScope(f, resourceID)
	b.emitRemediation(f, findingID)
}

// buildFindingProperties returns the property map for a Finding node,
// including SLA-breach and chain-membership extensions when present.
func buildFindingProperties(f *remediation.Finding) map[string]any {
	props := map[string]any{
		"finding_id":   f.FindingID,
		"control_id":   string(f.ControlID),
		"control_name": f.ControlName,
		"verdict":      "fail",
		"severity":     f.SeverityLabel(),
		"message":      f.TemporalRiskMessage(),
	}
	if f.IsOverdue() {
		props["sla_breached"] = true
	}
	if membership := f.ChainMembershipProperties(); membership != nil {
		// Post-process the per-entry stage_span: the core
		// projection emits raw kernel.AttackStage values; the
		// graph wire-format wants the ATT&CK-translated labels.
		// Keeping the translation in this adapter avoids
		// coupling core/evaluation to the providers/aws ATT&CK
		// vocabulary.
		for ci := range membership {
			if raw, ok := membership[ci]["stage_span"].([]kernel.AttackStage); ok {
				membership[ci]["stage_span"] = attack.TranslateStages(raw)
			}
		}
		props["x_stave_chain_membership"] = membership
	}
	return props
}

// emitControlNode emits the Control node for the finding's ControlID
// the first time that control is seen. Routes through emitOnce so the
// dedup invariant (any node ID emitted at most once) lives in one
// place rather than the per-category seenControls set the prior
// shape maintained — adding a new emit site can no longer forget the
// dedup pattern.
func (b *builderState) emitControlNode(f *remediation.Finding) {
	b.emitOnce(string(f.ControlID), Node{
		ID: string(f.ControlID), Type: NodeTypeControl,
		Standard: "oscal", StandardType: "control",
		Properties: map[string]any{
			"control_id":   string(f.ControlID),
			"control_name": f.ControlName,
			"severity":     f.SeverityLabel(),
		},
	})
}

// emitComplianceEdges emits ComplianceRequirement nodes plus MAPS_TO
// and VIOLATES_REQUIREMENT edges for each (framework, requirement)
// pair the control claims to satisfy.
func (b *builderState) emitComplianceEdges(f *remediation.Finding, findingID string) {
	for framework, reqID := range f.ControlCompliance {
		reqNodeID := string(framework) + ":" + string(reqID)
		if !b.seenRequirements.Contains(reqNodeID) {
			b.seenRequirements.Add(reqNodeID)
			b.g.Nodes = append(b.g.Nodes, Node{
				ID: reqNodeID, Type: NodeTypeComplianceRequirement,
				Standard: "oscal", StandardType: "control",
				Properties: map[string]any{
					"framework":      string(framework),
					"requirement_id": string(reqID),
				},
			})
		}
		mapsKey := string(f.ControlID) + "->" + reqNodeID
		if !b.seenMapsTo.Contains(mapsKey) {
			b.seenMapsTo.Add(mapsKey)
			b.g.Edges = append(b.g.Edges, Edge{
				From: string(f.ControlID), To: reqNodeID, Type: EdgeTypeMapsTo,
			})
		}
		violatesKey := findingID + "->" + reqNodeID
		if !b.seenViolates.Contains(violatesKey) {
			b.seenViolates.Add(violatesKey)
			b.g.Edges = append(b.g.Edges, Edge{
				From: findingID, To: reqNodeID, Type: EdgeTypeViolatesRequirement,
				Properties: map[string]any{"verdict": "fail"},
			})
		}
	}
}

// emitTenantScope emits the account-level TenantScope node and the
// BELONGS_TO_SCOPE edge from the finding's resource to that scope.
func (b *builderState) emitTenantScope(f *remediation.Finding, resourceID string) {
	acctID := extractAccountID(resourceID)
	if acctID == "" {
		return
	}
	scopeID := "account:" + acctID
	if !b.seenAccounts.Contains(acctID) {
		b.seenAccounts.Add(acctID)
		b.g.Nodes = append(b.g.Nodes, Node{
			ID: scopeID, Type: NodeTypeTenantScope,
			Standard: "ocsf", StandardType: "cloud.account",
			Properties: map[string]any{
				"account_id": acctID,
				"provider":   string(f.AssetVendor),
			},
		})
	}
	belongsKey := resourceID + "->" + scopeID
	if !b.seenBelongsTo.Contains(belongsKey) {
		b.seenBelongsTo.Add(belongsKey)
		b.g.Edges = append(b.g.Edges, Edge{
			From: resourceID, To: scopeID, Type: EdgeTypeBelongsToScope,
		})
	}
}

// emitRemediation emits the RemediationAction node and its
// HAS_REMEDIATION edge from the parent Finding. The edge is appended
// unconditionally for every Finding that names a RemediationAction so
// the post-pass dedup can merge identical edges from sibling findings.
func (b *builderState) emitRemediation(f *remediation.Finding, findingID string) {
	if !f.HasRemediationAction() {
		return
	}
	remID := "remediation_" + findingID
	b.emitOnce(remID, Node{
		ID: remID, Type: NodeTypeRemediationAction,
		Standard: "ocsf", StandardType: "Remediation Activity (9001)",
		Properties: map[string]any{
			"finding_id": findingID,
			"action":     f.RemediationSpec.Action,
		},
	})
	b.g.Edges = append(b.g.Edges, Edge{
		From: findingID, To: remID, Type: EdgeTypeHasRemediation,
	})
}

// processChainFinding emits the ThreatChain and AttackerCapability
// nodes for a chain finding, the PRODUCES edge between them, and the
// MEMBER_OF edges from each member finding back to the chain.
func (b *builderState) processChainFinding(
	cf *risk.CompoundFinding,
	findingsByControl map[kernel.ControlID][]int,
	findings []remediation.Finding,
) {
	chainID := string(cf.ChainID)

	memberControls := make([]string, len(cf.ControlsFailing))
	for j, cid := range cf.ControlsFailing {
		memberControls[j] = string(cid)
	}
	b.emitOnce(chainID, Node{
		ID: chainID, Type: NodeTypeThreatChain,
		Standard: "stix", StandardType: "Attack Pattern",
		Properties: map[string]any{
			"chain_id":          chainID,
			"narrative":         cf.Description,
			"compound_severity": cf.Severity.String(),
			"active":            true,
			"member_controls":   memberControls,
			"stage_span_stave":  cf.AttackStages,
			"stage_span_attck":  attack.TranslateStages(cf.AttackStages),
			"kill_chain_phases": attack.ToKillChainPhases(cf.AttackStages),
		},
	})

	// AttackerCapability node.
	capID := "capability_" + chainID
	b.emitOnce(capID, Node{
		ID: capID, Type: NodeTypeAttackerCapability,
		Standard: "stix", StandardType: "Attack Pattern",
		Properties: map[string]any{
			"chain_id":          chainID,
			"compound_severity": cf.Severity.String(),
			"stage_span_attck":  attack.TranslateStages(cf.AttackStages),
		},
	})

	// PRODUCES edge.
	b.g.Edges = append(b.g.Edges, Edge{
		From: chainID, To: capID, Type: EdgeTypeProduces,
	})

	// MEMBER_OF edges from findings to chain. O(1) lookup via the
	// pre-built control→[]findingIdx index.
	for _, ctlID := range cf.ControlsFailing {
		for _, j := range findingsByControl[ctlID] {
			ff := &findings[j]
			b.g.Edges = append(b.g.Edges, Edge{
				From: string(ff.FindingID), To: chainID, Type: EdgeTypeMemberOf,
				Properties: map[string]any{
					"chain_severity":   cf.Severity.String(),
					"stage_span_attck": attack.TranslateStages(cf.AttackStages),
				},
			})
		}
	}
}

// edgeKey is the deduplication key for graph edges. Using a struct (rather
// than a delimited string) avoids false collisions when node IDs contain
// the separator character — ARNs and resource paths legitimately include
// pipes, slashes, and colons.
type edgeKey struct {
	From, To string
	Type     EdgeType
}

// multiValueEdgeProps lists property keys whose multi-edge values
// must be preserved when deduplicating. The earlier dedup shape kept
// only the first-arriving value via "earliest wins"; for these keys
// that meant a finding belonging to chains of differing severity
// looked like it belonged to only the first chain. Promote
// conflicting values to a list under a sibling key so analysis
// consumers see every chain the edge participated in.
//
// The mapping is singular → plural (e.g. chain_severity →
// chain_severities) so callers can introspect either: the first
// value remains under the singular key for backward compatibility,
// and the full sorted set lives under the plural alias.
var multiValueEdgeProps = map[string]string{
	"chain_severity":   "chain_severities",
	"stage_span_attck": "stage_span_attck_all",
}

func deduplicateEdges(edges []Edge) []Edge {
	// Merge Properties on duplicate edges instead of dropping them.
	// Two builders may emit the same (From, To, Type) edge with
	// disjoint metadata (one carries verdict info, the other carries
	// an exposure window) — discarding the second loses analysis
	// downstream consumers depend on. Earlier-arriving keys win
	// scalar conflicts so output is deterministic, but a fixed set
	// of multi-valued keys (see multiValueEdgeProps) accumulate the
	// full set of distinct values across duplicates.
	seen := make(map[edgeKey]int, len(edges))
	out := make([]Edge, 0, len(edges))
	for _, e := range edges {
		k := edgeKey{From: e.From, To: e.To, Type: e.Type}
		if idx, dup := seen[k]; dup {
			if len(e.Properties) == 0 {
				continue
			}
			if out[idx].Properties == nil {
				out[idx].Properties = make(map[string]any, len(e.Properties))
			}
			mergeEdgeProperties(out[idx].Properties, e.Properties)
			continue
		}
		seen[k] = len(out)
		out = append(out, e)
	}
	finalizeMultiValueProps(out)
	return out
}

// mergeEdgeProperties layers `src` properties onto `dst`, keeping
// existing scalar values but accumulating distinct values under the
// multiValueEdgeProps singular keys. Accumulation goes into a sibling
// "<plural>" key so consumers can decide whether to read the
// first-seen scalar (singular) or the union (plural).
func mergeEdgeProperties(dst, src map[string]any) {
	for pk, pv := range src {
		pluralKey, isMulti := multiValueEdgeProps[pk]
		if !isMulti {
			if _, exists := dst[pk]; !exists {
				dst[pk] = pv
			}
			continue
		}
		// Always record under the singular key (first-write wins so the
		// existing scalar contract is preserved) and accumulate into
		// the plural-key set.
		if _, exists := dst[pk]; !exists {
			dst[pk] = pv
		}
		// If the plural key is already populated with something
		// other than the expected map[string]struct{} (e.g. a
		// caller pre-stamped a []string), warn before resetting:
		// the previous values are about to be discarded and the
		// silent rebuild made plural-key drift hard to diagnose.
		if existing, present := dst[pluralKey]; present {
			if _, ok := existing.(map[string]struct{}); !ok {
				slog.Warn("graph dedup: plural property has unexpected type, discarding existing values",
					"plural_key", pluralKey,
					"existing_type", fmt.Sprintf("%T", existing))
			}
		}
		// Build a fresh set seeded from any existing entries. The
		// expected shape is map[string]struct{} (the dedup
		// accumulator); legacy edges that landed here pre-stamped
		// with []string or a single string are also recovered
		// rather than silently discarded — the warn block above
		// already names the type-mismatch case for triage, but
		// data preservation across producer-version skew is the
		// safer default than data loss.
		newSet := make(map[string]struct{})
		switch existing := dst[pluralKey].(type) {
		case map[string]struct{}:
			for k := range existing {
				newSet[k] = struct{}{}
			}
		case []string:
			for _, s := range existing {
				newSet[s] = struct{}{}
			}
		case []any:
			for _, s := range existing {
				if s == nil {
					continue
				}
				newSet[fmt.Sprint(s)] = struct{}{}
			}
		case string:
			if existing != "" {
				newSet[existing] = struct{}{}
			}
		}
		// Multi-element property values must add each element to
		// the accumulator individually. The earlier `fmt.Sprint(pv)`
		// path coerced an entire []string into a single bracketed
		// string ("[a b c]"), so a downstream consumer expecting
		// separate entries saw one literal "[a b c]" entry instead
		// of three distinct values. Type-switch on slice shapes so
		// the per-element enumeration runs once at the merge site
		// rather than every consumer reparsing the bracketed form.
		switch typed := pv.(type) {
		case nil:
			// Skip nil values rather than letting fmt.Sprint
			// inject the literal "<nil>" into the accumulator
			// set. A nil pollutes downstream consumers with a
			// sentinel string that looks like a real value but
			// corresponds to no observed data.
		case []string:
			for _, s := range typed {
				if s != "" {
					newSet[s] = struct{}{}
				}
			}
		case []any:
			for _, elem := range typed {
				if elem == nil {
					continue
				}
				newSet[fmt.Sprint(elem)] = struct{}{}
			}
		default:
			newSet[fmt.Sprint(pv)] = struct{}{}
		}
		// Singular-rescue: also fold the existing scalar (set on the
		// first-edge write or by an earlier merge) into the plural
		// set so the union spans both the singular contract and
		// every duplicate's contribution. Apply the same per-element
		// expansion as the src-pv branch above so a singular value
		// that is itself a slice does not collapse into a literal
		// "[a b c]" string under fmt.Sprint.
		if existing, ok := dst[pk]; ok && existing != nil {
			switch typed := existing.(type) {
			case []string:
				for _, s := range typed {
					if s != "" {
						newSet[s] = struct{}{}
					}
				}
			case []any:
				for _, elem := range typed {
					if elem == nil {
						continue
					}
					newSet[fmt.Sprint(elem)] = struct{}{}
				}
			default:
				newSet[fmt.Sprint(existing)] = struct{}{}
			}
		}
		dst[pluralKey] = newSet
	}
}

// finalizeMultiValueProps converts the accumulated `map[string]struct{}`
// holding sets into stable sorted []string slices on every edge. The
// transient set form is an implementation detail of deduplicateEdges;
// downstream consumers see only the slice.
func finalizeMultiValueProps(edges []Edge) {
	for i := range edges {
		props := edges[i].Properties
		if props == nil {
			continue
		}
		for _, pluralKey := range multiValueEdgeProps {
			set, ok := props[pluralKey].(map[string]struct{})
			if !ok {
				continue
			}
			values := make([]string, 0, len(set))
			for v := range set {
				values = append(values, v)
			}
			slices.Sort(values)
			// Always emit the plural key, even for single-element
			// slices. The previous shape deleted it for len ≤ 1, so
			// downstream consumers had no reliable way to tell
			// "deduplicated to one value" from "no deduplication
			// happened" — the plural alias is the dedup signal, and
			// JSON consumers expect a stable shape across runs.
			props[pluralKey] = values
		}
	}
}

func computeMetadata(nodes []Node, edges []Edge) GraphMetadata {
	nodeTypes := make(map[NodeType]int)
	for _, n := range nodes {
		nodeTypes[n.Type]++
	}
	edgeTypes := make(map[EdgeType]int)
	for _, e := range edges {
		edgeTypes[e.Type]++
	}
	return GraphMetadata{
		NodeCount: len(nodes),
		EdgeCount: len(edges),
		NodeTypes: nodeTypes,
		EdgeTypes: edgeTypes,
	}
}

func extractAccountID(arn string) string {
	return iam.ExtractAccountID(arn)
}
