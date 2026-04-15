package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// stixRelTypeMap maps Stave edge types to STIX relationship types.
var stixRelTypeMap = map[string]string{
	"TARGETS":              "targets",
	"MEMBER_OF":            "indicates",
	"PRODUCES":             "uses",
	"BELONGS_TO_SCOPE":     "located-at",
	"MAPS_TO":              "related-to",
	"VIOLATES":             "related-to",
	"HAS_EFFECTIVE_ACCESS": "uses",
	"CAN_IMPERSONATE":      "impersonates",
}

// stixObjectTypeMap maps Stave node types to STIX object type prefixes.
var stixObjectTypeMap = map[string]string{
	"Finding":               "observed-data",
	"Resource":              "infrastructure",
	"Control":               "course-of-action",
	"ThreatChain":           "attack-pattern",
	"AttackerCapability":    "attack-pattern",
	"Identity":              "identity",
	"ComplianceRequirement": "course-of-action",
	"TenantScope":           "identity",
	"RemediationAction":     "course-of-action",
}

// MarshalSTIX writes a STIX 2.1 Bundle JSON from GraphData.
func MarshalSTIX(w io.Writer, g *GraphData) error {
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
			stixType = "x-stave-" + n.Type
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
		case "Finding":
			obj["first_observed"] = now
			obj["last_observed"] = now
			obj["number_observed"] = 1
			obj["extensions"] = map[string]any{
				"x_stave_finding": n.Properties,
			}
		case "Resource":
			obj["name"] = n.ID
			if rc, ok := n.Properties["resource_class"].(string); ok {
				obj["infrastructure_types"] = []string{rc}
			}
		case "ThreatChain":
			obj["name"] = n.ID
			if desc, ok := n.Properties["narrative"]; ok {
				obj["description"] = desc
			}
			if phases, ok := n.Properties["kill_chain_phases"]; ok {
				obj["kill_chain_phases"] = phases
			}
		case "AttackerCapability":
			obj["name"] = "Capability: " + n.ID
			if desc, ok := n.Properties["compound_severity"]; ok {
				obj["description"] = fmt.Sprintf("Chain capability — severity: %s", desc)
			}
		case "Control", "ComplianceRequirement", "RemediationAction":
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
		case "TenantScope":
			obj["name"] = "Account " + n.ID
			obj["identity_class"] = "organization"
		case "Identity":
			obj["name"] = n.ID
			obj["identity_class"] = "system"
		}

		objects = append(objects, obj)
	}

	// Edges → STIX relationships.
	for i := range g.Edges {
		e := &g.Edges[i]
		relType := stixRelTypeMap[e.Type]
		if relType == "" {
			relType = "related-to"
		}
		srcRef := nodeSTIXIDs[e.From]
		tgtRef := nodeSTIXIDs[e.To]
		if srcRef == "" || tgtRef == "" {
			continue
		}

		rel := map[string]any{
			"type":              "relationship",
			"id":                stixID("relationship", e.From+"|"+e.To+"|"+e.Type),
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
