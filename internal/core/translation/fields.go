package translation

import "maps"

// defaultFieldRegistry is the plain-language translation table for
// observation field paths that appear in shipped findings'
// ReasoningTrace output. Access via GetDefaultFieldRegistry() so the
// table cannot be mutated by callers.
//
// Entries are hand-maintained across the domain files:
//
//	fields_storage.go, fields_iam.go, fields_compute.go,
//	fields_network.go, fields_monitoring.go, fields_compliance.go.
func buildDefaultFieldRegistry() FieldRegistry { //nolint:gosec // G101 false positive: translation labels for property-path keys, not credentials.
	r := make(FieldRegistry, 1300)
	maps.Copy(r, storageFields())
	maps.Copy(r, identityFields())
	maps.Copy(r, computeFields())
	maps.Copy(r, networkFields())
	maps.Copy(r, monitoringFields())
	maps.Copy(r, complianceFields())
	return r
}

var defaultFieldRegistry = buildDefaultFieldRegistry()

// GetDefaultFieldRegistry returns the registry used by RenderClause
// for plain-language field translation.
func GetDefaultFieldRegistry() FieldRegistry {
	return defaultFieldRegistry
}
