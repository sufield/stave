package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_opensearch_domain — 109 controls. search_service.kind is the
// type discriminator; the access / audit / backup / capacity /
// crosscluster sub-trees each drive ~4 controls.
var opensearchSchema = Schema{
	AssetType: kernel.AssetType("aws_opensearch_domain"),
	Fields: []FieldRequirement{
		{Path: "properties.search_service.kind", Required: true,
			Doc: "type discriminator; every opensearch control gates on this"},
		{Path: "properties.search_service.access.fgac_enabled", Required: true,
			Doc: "fine-grained access control — load-bearing for the access family"},
		{Path: "properties.search_service.audit.enabled", Required: true,
			Doc: "audit-logging core for the audit control family"},
		{Path: "properties.search_service.backup.manual_repo_registered", Required: false,
			Doc: "backup-coverage signal; sparse-by-design when no manual repos exist"},
		{Path: "properties.search_service.capacity.is_production", Required: false,
			Doc: "capacity-class hint; sparse when no tag/heuristic resolves"},
		{Path: "properties.search_service.crosscluster.has_connections", Required: false,
			Doc: "cross-cluster topology; absent when no remote clusters"},
	},
}

func init() { Register(opensearchSchema) }
