package diag

import "testing"

func TestCodes_NotEmpty(t *testing.T) {
	// Verify canonical codes are non-empty strings.
	codes := []Code{
		CodeControlLoadFailed,
		CodeObservationLoadFailed,
		CodeControlMissingID,
		CodeSchemaViolation,
		CodeUnsupportedSchemaVersion,
		CodeNoControls,
		CodeNoSnapshots,
		CodeSingleSnapshot,
		CodeInvalidMaxUnsafe,
		CodeInvalidNowTime,
	}
	for _, c := range codes {
		if c == "" {
			t.Fatal("found empty code constant")
		}
	}
}

func TestCodes_Unique(t *testing.T) {
	codes := []Code{
		CodeControlLoadFailed, CodeObservationLoadFailed,
		CodeControlMissingID, CodeControlMissingName, CodeControlMissingDesc,
		CodeControlUndefinedParam, CodeControlBadDurationParam, CodeNowBeforeSnapshots,
		CodeNoControls, CodeControlBadIDFormat, CodeControlBadSeverity,
		CodeControlBadType, CodeControlEmptyPredicate, CodeControlUnsupportedOperator,
		CodeControlNeverMatches, CodeNoSnapshots, CodeSingleSnapshot,
		CodeDuplicateAssetID, CodeSnapshotsUnsorted, CodeDuplicateTimestamp,
		CodeSpanLessThanMaxUnsafe, CodeAssetIDReusedTypes, CodeAssetSingleAppearance,
		CodeAmbiguousTags,
		CodeSchemaViolation, CodeUnsupportedSchemaVersion,
		CodeInvalidMaxUnsafe, CodeInvalidNowTime,
		CodePackRegistryLoadFailed, CodeProjectConfigLoadFailed, CodeUnknownControlPack,
	}
	seen := make(map[Code]bool, len(codes))
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate code: %s", c)
		}
		seen[c] = true
	}
}
