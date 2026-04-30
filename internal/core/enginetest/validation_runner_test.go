package enginetest

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestValidateControlBadDurationParam(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		params    policy.ControlParams
		wantError bool
	}{
		{
			name:      "valid 0h",
			params:    policy.NewParams(map[string]any{"max_unsafe_duration": "0h"}),
			wantError: false,
		},
		{
			name:      "valid 24h",
			params:    policy.NewParams(map[string]any{"max_unsafe_duration": "24h"}),
			wantError: false,
		},
		{
			name:      "valid 7d",
			params:    policy.NewParams(map[string]any{"max_unsafe_duration": "7d"}),
			wantError: false,
		},
		{
			name:      "invalid garbage",
			params:    policy.NewParams(map[string]any{"max_unsafe_duration": "not-a-duration"}),
			wantError: true,
		},
		{
			name:      "invalid numeric without unit",
			params:    policy.NewParams(map[string]any{"max_unsafe_duration": "24"}),
			wantError: true,
		},
		{
			name:      "no param present",
			params:    policy.ControlParams{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl := policy.ControlDefinition{
				ID:          "CTL.TEST.001",
				Name:        "Test",
				Description: "Test control",
				Type:        policy.TypeUnsafeDuration,
				Params:      tt.params,
				UnsafePredicate: policy.UnsafePredicate{
					Any: []policy.PredicateRule{{Field: predicate.NewFieldPath("properties.x"), Op: predicate.OpEq, Value: policy.Bool(true)}},
				},
			}
			issues := ctl.Validate()

			hasBadDuration := false
			for _, issue := range issues {
				if issue.RuleID == diag.RuleControlBadDurationParam {
					hasBadDuration = true
				}
			}

			if tt.wantError && !hasBadDuration {
				t.Errorf("expected %s error for params %v, got none", diag.RuleControlBadDurationParam, tt.params)
			}
			if !tt.wantError && hasBadDuration {
				t.Errorf("unexpected %s error for params %v", diag.RuleControlBadDurationParam, tt.params)
			}
		})
	}
}

func TestValidationCodesUnique(t *testing.T) {
	t.Parallel()
	codes := []diag.RuleID{
		diag.RuleControlLoadFailed,
		diag.RuleObservationLoadFailed,
		diag.RuleControlMissingID,
		diag.RuleControlMissingName,
		diag.RuleControlMissingDesc,
		diag.RuleControlUndefinedParam,
		diag.RuleControlBadDurationParam,
		diag.RuleNowBeforeSnapshots,
		diag.RuleNoControls,
		diag.RuleControlBadIDFormat,
		diag.RuleControlBadType,
		diag.RuleControlEmptyPredicate,
		diag.RuleControlNeverMatches,
		diag.RuleNoSnapshots,
		diag.RuleSingleSnapshot,
		diag.RuleDuplicateAssetID,
		diag.RuleSnapshotsUnsorted,
		diag.RuleDuplicateTimestamp,
		diag.RuleSpanLessThanMaxUnsafe,
		diag.RuleAssetIDReusedTypes,
		diag.RuleAssetSingleAppearance,
	}
	seen := make(map[diag.RuleID]struct{})
	for _, c := range codes {
		if _, exists := seen[c]; exists {
			t.Errorf("duplicate validation code: %s", c)
		}
		seen[c] = struct{}{}
	}
}
