package graph

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// stixRelTypeMap maps Stave edge types to STIX relationship types.
var stixRelTypeMap = map[EdgeType]string{
	EdgeTypeTargets:             "targets",
	EdgeTypeMemberOf:            "indicates",
	EdgeTypeProduces:            "uses",
	EdgeTypeBelongsToScope:      "located-at",
	EdgeTypeMapsTo:              "related-to",
	EdgeTypeViolatesRequirement: "related-to",
	EdgeTypeViolates:            "related-to", // legacy alias, see builder.go
	EdgeTypeViolatesInvariant:   "related-to",
	EdgeTypeHasEffectiveAccess:  "uses",
	EdgeTypeCanImpersonate:      "impersonates",
	EdgeTypeHasRemediation:      "remediates",
	EdgeTypeGovernedBy:          "related-to",
}

// stixObjectTypeMap maps Stave node types to STIX object type prefixes.
var stixObjectTypeMap = map[NodeType]string{
	NodeTypeFinding:               "observed-data",
	NodeTypeResource:              "infrastructure",
	NodeTypeControl:               "course-of-action",
	NodeTypeThreatChain:           "attack-pattern",
	NodeTypeAttackerCapability:    "attack-pattern",
	NodeTypeIdentity:              "identity",
	NodeTypeComplianceRequirement: "course-of-action",
	NodeTypeTenantScope:           "identity",
	NodeTypeRemediationAction:     "course-of-action",
}

// MarshalSTIX writes a STIX 2.1 Bundle JSON from GraphData.
func MarshalSTIX(w io.Writer, g *GraphData) error {
	if g == nil {
		return errors.New("MarshalSTIX: nil GraphData")
	}
	now := g.GeneratedAt.Format(time.RFC3339)
	staveIdentityID := stixID("identity", "stave-assessment-producer")

	var objects []map[string]any

	// Stave producer identity.
	objects = append(objects, map[string]any{
		"type":           "identity",
		"id":             staveIdentityID,
		"spec_version":   "2.1",
		"name":           "Stave Security Assessment",
		"identity_class": "system",
		"created":        now,
		"modified":       now,
	})

	// Nodes → STIX objects.
	nodeSTIXIDs := make(map[string]string, len(g.Nodes))
	for i := range g.Nodes {
		n := &g.Nodes[i]
		stixType := stixObjectTypeMap[n.Type]
		if stixType == "" {
			stixType = "x-stave-" + string(n.Type)
		}

		sid := stixID(stixType, n.ID)
		nodeSTIXIDs[n.ID] = sid

		obj := map[string]any{
			"type":           stixType,
			"id":             sid,
			"spec_version":   "2.1",
			"created":        now,
			"modified":       now,
			"created_by_ref": staveIdentityID,
		}

		switch n.Type {
		case NodeTypeFinding:
			obj["first_observed"] = now
			obj["last_observed"] = now
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
			if name, ok := n.Properties["control_name"].(string); ok {
				obj["name"] = name
			} else if name, ok := n.Properties["action"].(string); ok {
				obj["name"] = name
			} else {
				obj["name"] = n.ID
			}
			if desc, ok := n.Properties["control_id"].(string); ok {
				obj["description"] = desc
			}
		case NodeTypeTenantScope:
			obj["name"] = "Account " + n.ID
			obj["identity_class"] = "organization"
		case NodeTypeIdentity:
			obj["name"] = n.ID
			obj["identity_class"] = "system"
		}

		objects = append(objects, obj)
	}

	// Edges → STIX relationships. Dangling edges are skipped with a
	// warning log so partial graph exports remain importable.
	var skipped int
	for i := range g.Edges {
		e := &g.Edges[i]
		relType := stixRelTypeMap[e.Type]
		if relType == "" {
			relType = "related-to"
		}
		srcRef := nodeSTIXIDs[e.From]
		tgtRef := nodeSTIXIDs[e.To]
		if srcRef == "" || tgtRef == "" {
			missing := "source"
			if srcRef != "" {
				missing = "target"
			}
			slog.Warn("graph: skipping dangling edge in stix export",
				"missing", missing,
				"from", e.From, "to", e.To, "type", e.Type)
			skipped++
			continue
		}

		rel := map[string]any{
			"type":              "relationship",
			"id":                stixID("relationship", e.From+"|"+e.To+"|"+string(e.Type)),
			"spec_version":      "2.1",
			"relationship_type": relType,
			"source_ref":        srcRef,
			"target_ref":        tgtRef,
			"created":           now,
			"modified":          now,
			"created_by_ref":    staveIdentityID,
		}
		objects = append(objects, rel)
	}
	if skipped > 0 {
		slog.Warn("graph: stix export skipped dangling edges",
			"skipped", skipped, "total_edges", len(g.Edges))
	}

	bundle := map[string]any{
		"type":         "bundle",
		"id":           stixID("bundle", g.Source.AssessmentOutput+now),
		"spec_version": "2.1",
		"objects":      objects,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

func stixID(objectType, content string) string {
	return objectType + "--" + uuidV5("stix", objectType, content)
}
