package diag

import "testing"

func TestRuleIDs_NotEmpty(t *testing.T) {
	// Verify canonical rule IDs are non-empty strings.
	rules := []RuleID{
		RuleControlLoadFailed,
		RuleObservationLoadFailed,
		RuleControlMissingID,
		RuleSchemaViolation,
		RuleUnsupportedSchemaVersion,
		RuleNoControls,
		RuleNoSnapshots,
		RuleSingleSnapshot,
		RuleInvalidMaxUnsafe,
		RuleInvalidNowTime,
	}
	for _, r := range rules {
		if r == "" {
			t.Fatal("found empty rule ID constant")
		}
	}
}

func TestRuleIDs_Unique(t *testing.T) {
	rules := []RuleID{
		RuleControlLoadFailed, RuleObservationLoadFailed,
		RuleControlMissingID, RuleControlMissingName, RuleControlMissingDesc,
		RuleControlUndefinedParam, RuleControlBadDurationParam, RuleNowBeforeSnapshots,
		RuleNoControls, RuleControlBadIDFormat, RuleControlBadSeverity,
		RuleControlBadType, RuleControlEmptyPredicate, RuleControlUnsupportedOperator,
		RuleControlNeverMatches, RuleNoSnapshots, RuleSingleSnapshot,
		RuleDuplicateAssetID, RuleSnapshotsUnsorted, RuleDuplicateTimestamp,
		RuleSpanLessThanMaxUnsafe, RuleAssetIDReusedTypes, RuleAssetSingleAppearance,
		RuleAmbiguousTags,
		RuleSchemaViolation, RuleUnsupportedSchemaVersion,
		RuleInvalidMaxUnsafe, RuleInvalidNowTime,
		RulePackRegistryLoadFailed, RuleProjectConfigLoadFailed, RuleUnknownControlPack,
	}
	seen := make(map[RuleID]struct{}, len(rules))
	for _, r := range rules {
		if _, ok := seen[r]; ok {
			t.Fatalf("duplicate rule ID: %s", r)
		}
		seen[r] = struct{}{}
	}
}
