package kernel

// Schema represents a wire-format contract version string written into
// JSON/YAML output fields like "schema_version" and "dsl_version". Values
// are enforced by embedded JSON Schema constraints (const/enum) and MUST
// NOT be changed without a coordinated schema migration.
type Schema string

func (s Schema) String() string { return string(s) }

// Core data schemas.
const (
	SchemaObservation Schema = "obs.v0.1"
	SchemaControl     Schema = "ctrl.v1"
	SchemaOutput      Schema = "out.v0.1"
	SchemaDiagnose    Schema = "diagnose.v1"
	SchemaDiff        Schema = "diff.v0.1"
)

// Command-specific output schemas.
const (
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
)

// Artifact envelope schemas.
const (
	SchemaCrosswalkResolution      Schema = "control-crosswalk-resolution.v1"
	SchemaSecurityAudit            Schema = "security-audit.v1"
	SchemaSecurityAuditArtifacts   Schema = "security-audit-artifacts.v1"
	SchemaSecurityAuditRunManifest Schema = "security-audit-run-manifest.v1"
	SchemaBugReport                Schema = "bug-report.v0.1"
	SchemaDemoReport               Schema = "demo-report.v0.1"
)

// Schema-loader registry keys — internal lookup keys for selecting which
// embedded .schema.json file to load via internal/contracts/schema.
// These are NOT wire-format strings; they never appear in JSON output.
const (
	// EmbeddedContractSchemaVersion is the directory version for most schemas
	// (control, observation, finding, diagnose) — resolves to
	// embedded/<kind>/v1/<kind>.schema.json.
	EmbeddedContractSchemaVersion = "v1"

	// OutputContractSchemaVersion is the directory version for the output
	// schema, which was published under a separate layout —
	// embedded/output/v0.1/output.schema.json.
	OutputContractSchemaVersion = "v0.1"
)
