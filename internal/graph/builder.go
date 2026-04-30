package graph

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/iam"
	"github.com/sufield/stave/internal/core/kernel"
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
	NodeCount int            `json:"node_count"`
	EdgeCount int            `json:"edge_count"`
	NodeTypes map[string]int `json:"node_types"`
	EdgeTypes map[string]int `json:"edge_types"`
}

// Node is a graph node with typed properties.
type Node struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Standard     string         `json:"standard"`
	StandardType string         `json:"standard_type"`
	Properties   map[string]any `json:"properties"`
}

// Edge is a graph edge with optional properties.
type Edge struct {
	From       string         `json:"from"`
	To         string         `json:"to"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties,omitempty"`
}

// BuildInput holds the data for graph construction.
type BuildInput struct {
	Findings      []remediation.Finding
	ChainFindings []risk.CompoundFinding
	Now           time.Time
	SourcePath    string
}

// Build constructs a GraphData from assessment output.
func Build(input BuildInput) *GraphData {
	g := &GraphData{
		SchemaVersion:   "1",
		OntologyVersion: "1.0",
		GeneratedAt:     input.Now,
		Source: GraphSource{
			AssessmentOutput: input.SourcePath,
		},
	}

	seenNodes := sets.New[string]()
	seenControls := sets.New[kernel.ControlID]()
	seenRequirements := sets.New[string]()
	seenAccounts := sets.New[string]()

	// Findings → Finding nodes, Resource nodes, Control nodes,
	// ComplianceRequirement nodes, TenantScope nodes, and edges.
	for i := range input.Findings {
		f := &input.Findings[i]

		// Finding node.
		findingID := f.FindingID
		if !seenNodes.Contains(findingID) {
			seenNodes.Add(findingID)
			props := map[string]any{
				"finding_id":   f.FindingID,
				"control_id":   string(f.ControlID),
				"control_name": f.ControlName,
				"verdict":      "fail",
				"severity":     f.ControlSeverity.String(),
				"message":      f.Evidence.TemporalRisk,
			}
			if f.SLABreached {
				props["sla_breached"] = true
			}
			if len(f.ChainMembership) > 0 {
				membership := make([]map[string]any, len(f.ChainMembership))
				for ci, cm := range f.ChainMembership {
					membership[ci] = map[string]any{
						"chain_id":       cm.ChainID,
						"chain_severity": cm.ChainSeverity,
						"stage_span":     TranslateStages(cm.StageSpan),
						"narrative":      cm.Narrative,
					}
				}
				props["x_stave_chain_membership"] = membership
			}
			g.Nodes = append(g.Nodes, Node{
				ID: findingID, Type: "Finding",
				Standard: "ocsf", StandardType: "Security Finding (2001)",
				Properties: props,
			})
		}

		// Resource node.
		resourceID := string(f.AssetID)
		if !seenNodes.Contains(resourceID) {
			seenNodes.Add(resourceID)
			providerType := string(f.AssetType)
			g.Nodes = append(g.Nodes, Node{
				ID: resourceID, Type: "Resource",
				Standard: "ocsf", StandardType: "Infrastructure",
				Properties: map[string]any{
					"resource_arn":   resourceID,
					"resource_class": ToResourceClass(providerType),
					"provider":       string(f.AssetVendor),
					"provider_type":  providerType,
					"account_id":     extractAccountID(resourceID),
				},
			})
		}

		// TARGETS edge.
		g.Edges = append(g.Edges, Edge{
			From: findingID, To: resourceID, Type: "TARGETS",
		})

		// Control node.
		if !seenControls.Contains(f.ControlID) {
			seenControls.Add(f.ControlID)
			g.Nodes = append(g.Nodes, Node{
				ID: string(f.ControlID), Type: "Control",
				Standard: "oscal", StandardType: "control",
				Properties: map[string]any{
					"control_id":   string(f.ControlID),
					"control_name": f.ControlName,
					"severity":     f.ControlSeverity.String(),
				},
			})
		}

		// ComplianceRequirement nodes + MAPS_TO + VIOLATES edges.
		for framework, reqID := range f.ControlCompliance {
			reqNodeID := string(framework) + ":" + reqID
			if !seenRequirements.Contains(reqNodeID) {
				seenRequirements.Add(reqNodeID)
				g.Nodes = append(g.Nodes, Node{
					ID: reqNodeID, Type: "ComplianceRequirement",
					Standard: "oscal", StandardType: "control",
					Properties: map[string]any{
						"framework":      string(framework),
						"requirement_id": reqID,
					},
				})
			}
			g.Edges = append(g.Edges, Edge{
				From: string(f.ControlID), To: reqNodeID, Type: "MAPS_TO",
			})
			g.Edges = append(g.Edges, Edge{
				From: findingID, To: reqNodeID, Type: "VIOLATES",
				Properties: map[string]any{"verdict": "fail"},
			})
		}

		// TenantScope node + BELONGS_TO_SCOPE edge.
		acctID := extractAccountID(resourceID)
		if acctID != "" {
			scopeID := "account:" + acctID
			if !seenAccounts.Contains(acctID) {
				seenAccounts.Add(acctID)
				g.Nodes = append(g.Nodes, Node{
					ID: scopeID, Type: "TenantScope",
					Standard: "ocsf", StandardType: "cloud.account",
					Properties: map[string]any{
						"account_id": acctID,
						"provider":   string(f.AssetVendor),
					},
				})
			}
			g.Edges = append(g.Edges, Edge{
				From: resourceID, To: scopeID, Type: "BELONGS_TO_SCOPE",
			})
		}

		// RemediationAction node + HAS_REMEDIATION edge from the parent
		// Finding. The edge is appended for every Finding that names a
		// RemediationAction (even if the node itself was already
		// recorded for a sibling finding) so dedup runs after.
		if f.RemediationSpec.Action != "" {
			remID := "remediation_" + findingID
			if !seenNodes.Contains(remID) {
				seenNodes.Add(remID)
				g.Nodes = append(g.Nodes, Node{
					ID: remID, Type: "RemediationAction",
					Standard: "ocsf", StandardType: "Remediation Activity (9001)",
					Properties: map[string]any{
						"finding_id": findingID,
						"action":     f.RemediationSpec.Action,
					},
				})
			}
			g.Edges = append(g.Edges, Edge{
				From: findingID, To: remID, Type: "HAS_REMEDIATION",
			})
		}
	}

	// Build a single index of findings keyed by control ID before
	// the chain loop. The previous nested-scan approach was O(N×M)
	// where N = ChainFindings × ControlsFailing and M = total
	// findings; on a 200-finding bundle with 20 chains that's ~4k
	// inner iterations per outer pass, all of which fed
	// deduplicateEdges with redundant copies anyway.
	findingsByControl := make(map[kernel.ControlID][]int, len(input.Findings))
	for j := range input.Findings {
		ff := &input.Findings[j]
		findingsByControl[ff.ControlID] = append(findingsByControl[ff.ControlID], j)
	}

	// ChainFindings → ThreatChain + AttackerCapability nodes and edges.
	for i := range input.ChainFindings {
		cf := &input.ChainFindings[i]
		chainID := cf.ChainID

		if !seenNodes.Contains(chainID) {
			seenNodes.Add(chainID)

			memberControls := make([]string, len(cf.ControlsFailing))
			for j, cid := range cf.ControlsFailing {
				memberControls[j] = string(cid)
			}

			g.Nodes = append(g.Nodes, Node{
				ID: chainID, Type: "ThreatChain",
				Standard: "stix", StandardType: "Attack Pattern",
				Properties: map[string]any{
					"chain_id":          chainID,
					"narrative":         cf.Description,
					"compound_severity": cf.Severity.String(),
					"active":            true,
					"member_controls":   memberControls,
					"stage_span_stave":  cf.AttackStages,
					"stage_span_attck":  TranslateStages(cf.AttackStages),
					"kill_chain_phases": ToKillChainPhases(cf.AttackStages),
				},
			})
		}

		// AttackerCapability node.
		capID := "capability_" + chainID
		if !seenNodes.Contains(capID) {
			seenNodes.Add(capID)
			g.Nodes = append(g.Nodes, Node{
				ID: capID, Type: "AttackerCapability",
				Standard: "stix", StandardType: "Attack Pattern",
				Properties: map[string]any{
					"chain_id":          chainID,
					"compound_severity": cf.Severity.String(),
					"stage_span_attck":  TranslateStages(cf.AttackStages),
				},
			})
		}

		// PRODUCES edge.
		g.Edges = append(g.Edges, Edge{
			From: chainID, To: capID, Type: "PRODUCES",
		})

		// MEMBER_OF edges from findings to chain. O(1) lookup via the
		// pre-built control→[]findingIdx index.
		for _, ctlID := range cf.ControlsFailing {
			for _, j := range findingsByControl[ctlID] {
				ff := &input.Findings[j]
				g.Edges = append(g.Edges, Edge{
					From: ff.FindingID, To: chainID, Type: "MEMBER_OF",
					Properties: map[string]any{
						"chain_severity":   cf.Severity.String(),
						"stage_span_attck": TranslateStages(cf.AttackStages),
					},
				})
			}
		}
	}

	// Deduplicate edges.
	g.Edges = deduplicateEdges(g.Edges)

	// Compute metadata.
	g.Metadata = computeMetadata(g.Nodes, g.Edges)

	return g
}

// edgeKey is the deduplication key for graph edges. Using a struct (rather
// than a delimited string) avoids false collisions when node IDs contain
// the separator character — ARNs and resource paths legitimately include
// pipes, slashes, and colons.
type edgeKey struct {
	From, To, Type string
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
		set := asAnySet(dst[pluralKey])
		set[fmt.Sprint(pv)] = struct{}{}
		set[fmt.Sprint(dst[pk])] = struct{}{}
		dst[pluralKey] = set
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
			if len(values) <= 1 {
				// A single value adds no information beyond the
				// singular key — drop the plural alias to keep
				// outputs minimal for the common case.
				delete(props, pluralKey)
				continue
			}
			props[pluralKey] = values
		}
	}
}

// asAnySet returns the input as a map[string]struct{} accumulator.
// A nil input legitimately falls through to the new-map path (first
// merge into the plural slot). A non-nil input of any other concrete
// type is unexpected — callers should have run a type-check first;
// this function logs and returns a fresh map so the merge can
// proceed rather than panic, but the warning surfaces the data loss.
func asAnySet(v any) map[string]struct{} {
	if v == nil {
		return make(map[string]struct{}, 2)
	}
	if s, ok := v.(map[string]struct{}); ok {
		return s
	}
	slog.Warn("graph dedup: asAnySet given non-set type, discarding existing values",
		"type", fmt.Sprintf("%T", v))
	return make(map[string]struct{}, 2)
}

func computeMetadata(nodes []Node, edges []Edge) GraphMetadata {
	nodeTypes := make(map[string]int)
	for _, n := range nodes {
		nodeTypes[n.Type]++
	}
	edgeTypes := make(map[string]int)
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
