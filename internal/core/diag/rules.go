package diag

// RuleID is a typed identifier for a security rule that was evaluated.
type RuleID string

// Canonical rule IDs for validation and contract diagnostics.
const (
	// Errors (blocking) - loading failures
	RuleControlLoadFailed     RuleID = "CONTROL_LOAD_FAILED"
	RuleObservationLoadFailed RuleID = "OBSERVATION_LOAD_FAILED"

	// Errors (blocking) - structural issues
	RuleControlMissingID        RuleID = "CONTROL_MISSING_ID"
	RuleControlMissingName      RuleID = "CONTROL_MISSING_NAME"
	RuleControlMissingDesc      RuleID = "CONTROL_MISSING_DESCRIPTION"
	RuleControlUndefinedParam   RuleID = "CONTROL_UNDEFINED_PARAM"
	RuleControlBadDurationParam RuleID = "CONTROL_BAD_DURATION_PARAM"
	RuleNowBeforeSnapshots      RuleID = "NOW_BEFORE_SNAPSHOTS"

	// Warnings (non-blocking)
	RuleNoControls                 RuleID = "NO_CONTROLS"
	RuleControlBadIDFormat         RuleID = "CONTROL_BAD_ID_FORMAT"
	RuleControlBadSeverity         RuleID = "CONTROL_BAD_SEVERITY"
	RuleControlBadType             RuleID = "CONTROL_BAD_TYPE"
	RuleControlEmptyPredicate      RuleID = "CONTROL_EMPTY_PREDICATE"
	RuleControlUnsupportedOperator RuleID = "CONTROL_UNSUPPORTED_OPERATOR"
	RuleControlNeverMatches        RuleID = "CONTROL_NEVER_MATCHES"
	RuleNoSnapshots                RuleID = "NO_SNAPSHOTS"
	RuleSingleSnapshot             RuleID = "SINGLE_SNAPSHOT"
	RuleDuplicateAssetID           RuleID = "DUPLICATE_ASSET_ID"
	RuleSnapshotsUnsorted          RuleID = "SNAPSHOTS_UNSORTED"
	RuleDuplicateTimestamp         RuleID = "DUPLICATE_TIMESTAMP"
	RuleSpanLessThanMaxUnsafe      RuleID = "SPAN_LESS_THAN_MAX_UNSAFE"
	RuleAssetIDReusedTypes         RuleID = "ASSET_ID_REUSED_TYPES"
	RuleAssetSingleAppearance      RuleID = "ASSET_SINGLE_APPEARANCE"
	RuleAmbiguousTags              RuleID = "AMBIGUOUS_TAGS"

	// Contract/schema validation.
	RuleSchemaViolation          RuleID = "SCHEMA_VIOLATION"
	RuleUnsupportedSchemaVersion RuleID = "UNSUPPORTED_SCHEMA_VERSION"

	// CLI parameter validation.
	RuleInvalidMaxUnsafe        RuleID = "INVALID_MAX_UNSAFE"
	RuleInvalidNowTime          RuleID = "INVALID_NOW_TIME"
	RulePackRegistryLoadFailed  RuleID = "PACK_REGISTRY_LOAD_FAILED"
	RuleProjectConfigLoadFailed RuleID = "PROJECT_CONFIG_LOAD_FAILED"
	RuleUnknownControlPack      RuleID = "UNKNOWN_CONTROL_PACK"
)
