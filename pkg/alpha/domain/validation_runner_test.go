package domain

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

func TestValidateControlBadDurationParam(t *testing.T) {
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
			issues := policy.ValidateControlDefinition(&ctl)

			hasBadDuration := false
			for _, issue := range issues {
				if issue.Code == diag.CodeControlBadDurationParam {
					hasBadDuration = true
				}
			}

			if tt.wantError && !hasBadDuration {
				t.Errorf("expected %s error for params %v, got none", diag.CodeControlBadDurationParam, tt.params)
			}
			if !tt.wantError && hasBadDuration {
				t.Errorf("unexpected %s error for params %v", diag.CodeControlBadDurationParam, tt.params)
			}
		})
	}
}

func TestValidationCodesUnique(t *testing.T) {
	codes := []diag.Code{
		diag.CodeControlLoadFailed,
		diag.CodeObservationLoadFailed,
		diag.CodeControlMissingID,
		diag.CodeControlMissingName,
		diag.CodeControlMissingDesc,
		diag.CodeControlUndefinedParam,
		diag.CodeControlBadDurationParam,
		diag.CodeNowBeforeSnapshots,
		diag.CodeNoControls,
		diag.CodeControlBadIDFormat,
		diag.CodeControlBadType,
		diag.CodeControlEmptyPredicate,
		diag.CodeControlNeverMatches,
		diag.CodeNoSnapshots,
		diag.CodeSingleSnapshot,
		diag.CodeDuplicateAssetID,
		diag.CodeSnapshotsUnsorted,
		diag.CodeDuplicateTimestamp,
		diag.CodeSpanLessThanMaxUnsafe,
		diag.CodeAssetIDReusedTypes,
		diag.CodeAssetSingleAppearance,
	}
	seen := make(map[diag.Code]struct{})
	for _, c := range codes {
		if _, exists := seen[c]; exists {
			t.Errorf("duplicate validation code: %s", c)
		}
		seen[c] = struct{}{}
	}
}
