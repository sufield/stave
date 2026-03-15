package kernel

// Schema represents a stable wire-format contract version string.
// These values are written into "schema_version" fields in JSON/YAML.
// Modification of these strings requires a coordinated schema migration.
type Schema string

func (s Schema) String() string { return string(s) }

const (
	// --- Core Data Schemas ---
	SchemaObservation Schema = "obs.v0.1"
	SchemaControl     Schema = "ctrl.v1"
	SchemaOutput      Schema = "out.v0.1"
	SchemaDiagnose    Schema = "diagnose.v1"
	SchemaDiff        Schema = "diff.v0.1"

	// --- Command-Specific Schemas ---
	SchemaBaseline        Schema = "baseline.v0.1"
	SchemaEnforce         Schema = "enforce.v0.1"
	SchemaGate            Schema = "gate.v0.1"
	SchemaValidate        Schema = "validate.v0.1"
	SchemaSnapshotPlan    Schema = "snapshot_plan.v0.1"
	SchemaSnapshotPrune   Schema = "snapshot_prune.v0.1"
	SchemaSnapshotQuality Schema = "snapshot_quality.v0.1"
	SchemaSnapshotArchive Schema = "snapshot_archive.v0.1"
	SchemaCIDiff          Schema = "ci_diff.v0.1"
	SchemaFixLoop         Schema = "fix_loop.v0.1"

	// --- Artifact & Audit Schemas ---
	SchemaCrosswalkResolution      Schema = "control-crosswalk-resolution.v1"
	SchemaSecurityAudit            Schema = "security-audit.v1"
	SchemaSecurityAuditArtifacts   Schema = "security-audit-artifacts.v1"
	SchemaSecurityAuditRunManifest Schema = "security-audit-run-manifest.v1"
	SchemaBugReport                Schema = "bug-report.v0.1"
)

// validSchemas enables fast membership checks for validation.
var validSchemas = map[Schema]struct{}{
	SchemaObservation:              {},
	SchemaControl:                  {},
	SchemaOutput:                   {},
	SchemaDiagnose:                 {},
	SchemaDiff:                     {},
	SchemaBaseline:                 {},
	SchemaEnforce:                  {},
	SchemaGate:                     {},
	SchemaValidate:                 {},
	SchemaSnapshotPlan:             {},
	SchemaSnapshotPrune:            {},
	SchemaSnapshotQuality:          {},
	SchemaSnapshotArchive:          {},
	SchemaCIDiff:                   {},
	SchemaFixLoop:                  {},
	SchemaCrosswalkResolution:      {},
	SchemaSecurityAudit:            {},
	SchemaSecurityAuditArtifacts:   {},
	SchemaSecurityAuditRunManifest: {},
	SchemaBugReport:                {},
}

// IsValid reports whether the schema version is recognized by the system.
func (s Schema) IsValid() bool {
	_, ok := validSchemas[s]
	return ok
}

// Internal Registry Keys
// These are used by the loader to locate embedded .schema.json files.
// They are NOT wire-format strings and never appear in JSON output.
const (
	// RegistryLayoutStandard is the directory key for modern schemas
	// (control, observation, finding, diagnose).
	RegistryLayoutStandard = "v1"

	// RegistryLayoutLegacyOutput is the directory key for the output schema,
	// published under a separate layout.
	RegistryLayoutLegacyOutput = "v0.1"
)
