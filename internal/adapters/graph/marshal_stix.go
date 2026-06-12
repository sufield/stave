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
		return errors.New("marshalSTIX: nil GraphData")
	}
	now := g.GeneratedAt.UTC()
	nowStr := now.Format(time.RFC3339)
	staveIdentityID := stixID("identity", "stave-assessment-producer")

	var objects []map[string]any

	// Stave producer identity.
	objects = append(objects, map[string]any{
		"type":           "identity",
		"id":             staveIdentityID,
		"spec_version":   "2.1",
		"name":           "Stave Security Assessment",
		"identity_class": "system",
		"created":        nowStr,
		"modified":       nowStr,
	})

	// Nodes → STIX objects. The per-type switch lives on Node now;
	// this loop just records the issued ID and appends the object.
	nodeSTIXIDs := make(map[string]string, len(g.Nodes))
	for i := range g.Nodes {
		n := &g.Nodes[i]
		sid, obj := n.STIXObject(now, staveIdentityID)
		nodeSTIXIDs[n.ID] = sid
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
			"created":           nowStr,
			"modified":          nowStr,
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
		"id":           stixID("bundle", g.Source.AssessmentOutput+nowStr),
		"spec_version": "2.1",
		"objects":      objects,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		return fmt.Errorf("encode STIX bundle: %w", err)
	}
	return nil
}

func stixID(objectType, content string) string {
	return objectType + "--" + uuidV5("stix", objectType, content)
}
