package diag

// Canonical issue codes for validation and contract diagnostics.
const (
	// Errors (blocking) - loading failures
	CodeControlLoadFailed     = "CONTROL_LOAD_FAILED"
	CodeObservationLoadFailed = "OBSERVATION_LOAD_FAILED"

	// Errors (blocking) - structural issues
	CodeControlMissingID        = "CONTROL_MISSING_ID"
	CodeControlMissingName      = "CONTROL_MISSING_NAME"
	CodeControlMissingDesc      = "CONTROL_MISSING_DESCRIPTION"
	CodeControlUndefinedParam   = "CONTROL_UNDEFINED_PARAM"
	CodeControlBadDurationParam = "CONTROL_BAD_DURATION_PARAM"
	CodeNowBeforeSnapshots      = "NOW_BEFORE_SNAPSHOTS"

	// Warnings (non-blocking)
	CodeNoControls            = "NO_CONTROLS"
	CodeControlBadIDFormat    = "CONTROL_BAD_ID_FORMAT"
	CodeControlBadSeverity    = "CONTROL_BAD_SEVERITY"
	CodeControlBadType        = "CONTROL_BAD_TYPE"
	CodeControlEmptyPredicate = "CONTROL_EMPTY_PREDICATE"
	CodeControlNeverMatches   = "CONTROL_NEVER_MATCHES"
	CodeNoSnapshots           = "NO_SNAPSHOTS"
	CodeSingleSnapshot        = "SINGLE_SNAPSHOT"
	CodeDuplicateResourceID   = "DUPLICATE_RESOURCE_ID"
	CodeSnapshotsUnsorted     = "SNAPSHOTS_UNSORTED"
	CodeDuplicateTimestamp    = "DUPLICATE_TIMESTAMP"
	CodeSpanLessThanMaxUnsafe = "SPAN_LESS_THAN_MAX_UNSAFE"
	CodeAssetIDReusedTypes    = "RESOURCE_ID_REUSED_TYPES"
	CodeAssetSingleAppearance = "RESOURCE_SINGLE_APPEARANCE"
	CodeAmbiguousTags         = "AMBIGUOUS_TAGS"

	// Contract/schema validation.
	CodeSchemaViolation          = "SCHEMA_VIOLATION"
	CodeUnsupportedSchemaVersion = "UNSUPPORTED_SCHEMA_VERSION"
)
