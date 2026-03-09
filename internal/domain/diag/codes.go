package diag

// Code is a typed diagnostic code for validation and contract diagnostics.
type Code string

// Canonical issue codes for validation and contract diagnostics.
const (
	// Errors (blocking) - loading failures
	CodeControlLoadFailed     Code = "CONTROL_LOAD_FAILED"
	CodeObservationLoadFailed Code = "OBSERVATION_LOAD_FAILED"

	// Errors (blocking) - structural issues
	CodeControlMissingID        Code = "CONTROL_MISSING_ID"
	CodeControlMissingName      Code = "CONTROL_MISSING_NAME"
	CodeControlMissingDesc      Code = "CONTROL_MISSING_DESCRIPTION"
	CodeControlUndefinedParam   Code = "CONTROL_UNDEFINED_PARAM"
	CodeControlBadDurationParam Code = "CONTROL_BAD_DURATION_PARAM"
	CodeNowBeforeSnapshots      Code = "NOW_BEFORE_SNAPSHOTS"

	// Warnings (non-blocking)
	CodeNoControls            Code = "NO_CONTROLS"
	CodeControlBadIDFormat    Code = "CONTROL_BAD_ID_FORMAT"
	CodeControlBadSeverity    Code = "CONTROL_BAD_SEVERITY"
	CodeControlBadType        Code = "CONTROL_BAD_TYPE"
	CodeControlEmptyPredicate Code = "CONTROL_EMPTY_PREDICATE"
	CodeControlNeverMatches   Code = "CONTROL_NEVER_MATCHES"
	CodeNoSnapshots           Code = "NO_SNAPSHOTS"
	CodeSingleSnapshot        Code = "SINGLE_SNAPSHOT"
	CodeDuplicateAssetID      Code = "DUPLICATE_ASSET_ID"
	CodeSnapshotsUnsorted     Code = "SNAPSHOTS_UNSORTED"
	CodeDuplicateTimestamp    Code = "DUPLICATE_TIMESTAMP"
	CodeSpanLessThanMaxUnsafe Code = "SPAN_LESS_THAN_MAX_UNSAFE"
	CodeAssetIDReusedTypes    Code = "ASSET_ID_REUSED_TYPES"
	CodeAssetSingleAppearance Code = "ASSET_SINGLE_APPEARANCE"
	CodeAmbiguousTags         Code = "AMBIGUOUS_TAGS"

	// Contract/schema validation.
	CodeSchemaViolation          Code = "SCHEMA_VIOLATION"
	CodeUnsupportedSchemaVersion Code = "UNSUPPORTED_SCHEMA_VERSION"

	// CLI parameter validation.
	CodeInvalidMaxUnsafe       Code = "INVALID_MAX_UNSAFE"
	CodeInvalidNowTime         Code = "INVALID_NOW_TIME"
	CodePackRegistryLoadFailed Code = "PACK_REGISTRY_LOAD_FAILED"
	CodeUnknownControlPack     Code = "UNKNOWN_CONTROL_PACK"
)
