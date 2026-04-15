package graph

import (
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
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

	seenNodes := make(map[string]bool)
	seenControls := make(map[kernel.ControlID]bool)
	seenRequirements := make(map[string]bool)
	seenAccounts := make(map[string]bool)

	// Findings → Finding nodes, Resource nodes, Control nodes,
	// ComplianceRequirement nodes, TenantScope nodes, and edges.
	for i := range input.Findings {
		f := &input.Findings[i]

		// Finding node.
		findingID := f.FindingID
		if !seenNodes[findingID] {
			seenNodes[findingID] = true
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
		if !seenNodes[resourceID] {
			seenNodes[resourceID] = true
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
		if !seenControls[f.ControlID] {
			seenControls[f.ControlID] = true
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
			if !seenRequirements[reqNodeID] {
				seenRequirements[reqNodeID] = true
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
			if !seenAccounts[acctID] {
				seenAccounts[acctID] = true
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

		// RemediationAction node.
		if f.RemediationSpec.Action != "" {
			remID := "remediation_" + findingID
			if !seenNodes[remID] {
				seenNodes[remID] = true
				g.Nodes = append(g.Nodes, Node{
					ID: remID, Type: "RemediationAction",
					Standard: "ocsf", StandardType: "Remediation Activity (9001)",
					Properties: map[string]any{
						"finding_id": findingID,
						"action":     f.RemediationSpec.Action,
					},
				})
			}
		}
	}

	// ChainFindings → ThreatChain + AttackerCapability nodes and edges.
	for i := range input.ChainFindings {
		cf := &input.ChainFindings[i]
		chainID := cf.ChainID

		if !seenNodes[chainID] {
			seenNodes[chainID] = true

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
		if !seenNodes[capID] {
			seenNodes[capID] = true
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

		// MEMBER_OF edges from findings to chain.
		for _, ctlID := range cf.ControlsFailing {
			for j := range input.Findings {
				ff := &input.Findings[j]
				if ff.ControlID == ctlID {
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
	}

	// Deduplicate edges.
	g.Edges = deduplicateEdges(g.Edges)

	// Compute metadata.
	g.Metadata = computeMetadata(g.Nodes, g.Edges)

	return g
}

func deduplicateEdges(edges []Edge) []Edge {
	seen := make(map[string]bool, len(edges))
	out := make([]Edge, 0, len(edges))
	for _, e := range edges {
		key := e.From + "|" + e.To + "|" + e.Type
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
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
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
