package kernel

// Schema represents a stable wire-format contract version string.
// These values are written into "schema_version" fields in JSON/YAML.
// Modification of these strings requires a coordinated schema migration.
type Schema string

func (s Schema) String() string { return string(s) }

// Wire-format schema version constants.
const (
	// SchemaObservation is the schema version for observation snapshots.
	SchemaObservation Schema = "obs.v0.1"
	// SchemaControl is the schema version for control definitions.
	SchemaControl Schema = "ctrl.v1"
	// SchemaOutput is the schema version for evaluation output.
	SchemaOutput Schema = "out.v0.1"
	// SchemaDiagnose is the schema version for diagnostic output.
	SchemaDiagnose Schema = "diagnose.v1"
	// SchemaDiff is the schema version for diff output.
	SchemaDiff Schema = "diff.v0.1"

	// SchemaBaseline is the schema version for baseline artifacts.
	SchemaBaseline Schema = "baseline.v0.1"
	// SchemaEnforce is the schema version for enforcement output.
	SchemaEnforce Schema = "enforce.v0.1"
	// SchemaGate is the schema version for gate check output.
	SchemaGate Schema = "gate.v0.1"
	// SchemaLint is the schema version for lint output.
	SchemaLint Schema = "lint.v0.1"
	// SchemaSnapshotPlan is the schema version for snapshot plan output.
	SchemaSnapshotPlan Schema = "snapshot_plan.v0.1"
	// SchemaSnapshotQuality is the schema version for snapshot quality output.
	SchemaSnapshotQuality Schema = "snapshot_quality.v0.1"
	// SchemaSnapshotArchive is the schema version for snapshot archive output.
	SchemaSnapshotArchive Schema = "snapshot_archive.v0.1"
	// SchemaCIDiff is the schema version for CI diff output.
	SchemaCIDiff Schema = "ci_diff.v0.1"
	// SchemaFixLoop is the schema version for fix loop output.
	SchemaFixLoop Schema = "fix_loop.v0.1"

	// SchemaCrosswalkResolution is the schema version for crosswalk resolution output.
	SchemaCrosswalkResolution Schema = "control-crosswalk-resolution.v1"
	// SchemaSecurityAudit is the schema version for security audit reports.
	SchemaSecurityAudit Schema = "security-audit.v1"
	// SchemaSecurityAuditArtifacts is the schema version for security audit artifact manifests.
	SchemaSecurityAuditArtifacts Schema = "security-audit-artifacts.v1"
	// SchemaSecurityAuditRunManifest is the schema version for security audit run manifests.
	SchemaSecurityAuditRunManifest Schema = "security-audit-run-manifest.v1"
	// SchemaBugReport is the schema version for bug report output.
	SchemaBugReport Schema = "bug-report.v0.1"
)

// validSchemas enables fast membership checks for validation.
var validSchemas = NewEnumSet(
	SchemaObservation,
	SchemaControl,
	SchemaOutput,
	SchemaDiagnose,
	SchemaDiff,
	SchemaBaseline,
	SchemaEnforce,
	SchemaGate,
	SchemaLint,
	SchemaSnapshotPlan,
	SchemaSnapshotQuality,
	SchemaSnapshotArchive,
	SchemaCIDiff,
	SchemaFixLoop,
	SchemaCrosswalkResolution,
	SchemaSecurityAudit,
	SchemaSecurityAuditArtifacts,
	SchemaSecurityAuditRunManifest,
	SchemaBugReport,
)

// IsValid reports whether the schema version is recognized by the system.
func (s Schema) IsValid() bool {
	return validSchemas.Contains(s)
}

// RegistryLayoutStandard is the directory key used by the schema loader to
// locate embedded .schema.json files. All schema kinds use this layout.
// This is NOT a wire-format string and never appears in JSON output.
const RegistryLayoutStandard = "v1"
