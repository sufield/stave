package domain

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// TestParseDuration tests ParseDuration with various duration formats.
func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"168h", 168 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"1d12h", 36 * time.Hour, false},                  // combined format
		{"2d6h30m", 54*time.Hour + 30*time.Minute, false}, // combined format
		{"1d2m", 24*time.Hour + 2*time.Minute, false},
		{"1d1.5h", 25*time.Hour + 30*time.Minute, false},
		{"-7d", 0, true},  // negative days
		{"-24h", 0, true}, // negative hours
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := kernel.ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("kernel.ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("kernel.ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestPredicateRuleMatches tests the policy.PredicateRule.Matches method with various operators and values.
func TestPredicateRuleMatches(t *testing.T) {
	resource := asset.Asset{
		ID:   "test-resource",
		Type: kernel.AssetType("storage_bucket"),
		Properties: map[string]any{
			"public": true,
			"acl":    "public-read",
			"count":  42,
		},
	}

	tests := []struct {
		name     string
		rule     policy.PredicateRule
		expected bool
	}{
		{
			name:     "bool equality - true",
			rule:     policy.PredicateRule{Field: "properties.public", Op: "eq", Value: true},
			expected: true,
		},
		{
			name:     "bool equality - false",
			rule:     policy.PredicateRule{Field: "properties.public", Op: "eq", Value: false},
			expected: false,
		},
		{
			name:     "string equality",
			rule:     policy.PredicateRule{Field: "properties.acl", Op: "eq", Value: "public-read"},
			expected: true,
		},
		{
			name:     "string inequality",
			rule:     policy.PredicateRule{Field: "properties.acl", Op: "eq", Value: "private"},
			expected: false,
		},
		{
			name:     "int equality",
			rule:     policy.PredicateRule{Field: "properties.count", Op: "eq", Value: 42},
			expected: true,
		},
		{
			name:     "non-existent field",
			rule:     policy.PredicateRule{Field: "properties.missing", Op: "eq", Value: true},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.Matches(resource)
			if got != tt.expected {
				t.Errorf("policy.PredicateRule.Matches() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUnsafePredicateEvaluate tests the policy.UnsafePredicate.Evaluate method with basic boolean logic.
func TestUnsafePredicateEvaluate(t *testing.T) {
	publicResource := asset.Asset{
		ID:         "public-bucket",
		Properties: map[string]any{"public": true},
	}

	privateResource := asset.Asset{
		ID:         "private-bucket",
		Properties: map[string]any{"public": false},
	}

	predicate := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: "properties.public", Op: "eq", Value: true},
		},
	}

	if !predicate.Evaluate(publicResource, nil) {
		t.Error("Expected public resource to be unsafe")
	}

	if predicate.Evaluate(privateResource, nil) {
		t.Error("Expected private resource to be safe")
	}
}

// TestIdentityBlastRadiusPredicate tests CTL.ID.AUTHZ.002 predicate evaluation.
func TestIdentityBlastRadiusPredicate(t *testing.T) {
	// CTL.ID.AUTHZ.002 predicate structure (simplified for testing)
	predicate := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			// Missing owner or purpose
			{
				Any: []policy.PredicateRule{
					{Field: "identity.owner", Op: "missing", Value: true},
					{Field: "identity.purpose", Op: "missing", Value: true},
				},
			},
			// Wildcard with forbid_wildcards
			{
				All: []policy.PredicateRule{
					{Field: "identity.grants.has_wildcard", Op: "eq", Value: true},
					{Field: "params.forbid_wildcards", Op: "eq", Value: true},
				},
			},
			// Too many systems
			{Field: "identity.scope.distinct_systems", Op: "gt", ValueFromParam: "max_systems"},
			// Too many asset groups
			{Field: "identity.scope.distinct_resource_groups", Op: "gt", ValueFromParam: "max_resource_groups"},
		},
	}

	params := policy.ControlParams{
		"max_systems":         1,
		"max_resource_groups": 1,
		"forbid_wildcards":    true,
		"require_owner":       true,
		"require_purpose":     true,
	}

	tests := []struct {
		name     string
		identity asset.CloudIdentity
		wantSafe bool
	}{
		{
			name: "A) Missing owner => UNSAFE",
			identity: asset.CloudIdentity{
				ID: "role:missing-owner",
				Properties: map[string]any{
					"purpose": "testing",
					"grants": map[string]any{
						"has_wildcard": false,
					},
					"scope": map[string]any{
						"distinct_systems":         1,
						"distinct_resource_groups": 1,
					},
				},
			},
			wantSafe: false,
		},
		{
			name: "B) Missing purpose => UNSAFE",
			identity: asset.CloudIdentity{
				ID: "role:missing-purpose",
				Properties: map[string]any{
					"owner": "team-a",
					"grants": map[string]any{
						"has_wildcard": false,
					},
					"scope": map[string]any{
						"distinct_systems":         1,
						"distinct_resource_groups": 1,
					},
				},
			},
			wantSafe: false,
		},
		{
			name: "C) Wildcard grant with forbid_wildcards=true => UNSAFE",
			identity: asset.CloudIdentity{
				ID: "role:wildcard-role",
				Properties: map[string]any{
					"owner":   "team-b",
					"purpose": "admin tasks",
					"grants": map[string]any{
						"has_wildcard": true,
					},
					"scope": map[string]any{
						"distinct_systems":         1,
						"distinct_resource_groups": 1,
					},
				},
			},
			wantSafe: false,
		},
		{
			name: "D) DistinctSystems=2 > max_systems=1 => UNSAFE",
			identity: asset.CloudIdentity{
				ID: "role:too-many-systems",
				Properties: map[string]any{
					"owner":   "team-c",
					"purpose": "cross-system access",
					"grants": map[string]any{
						"has_wildcard": false,
					},
					"scope": map[string]any{
						"distinct_systems":         2, // 2 > 1
						"distinct_resource_groups": 1,
					},
				},
			},
			wantSafe: false,
		},
		{
			name: "E) DistinctResourceGroups=3 > max_resource_groups=1 => UNSAFE",
			identity: asset.CloudIdentity{
				ID: "role:too-many-groups",
				Properties: map[string]any{
					"owner":   "team-d",
					"purpose": "multi-group access",
					"grants": map[string]any{
						"has_wildcard": false,
					},
					"scope": map[string]any{
						"distinct_systems":         1,
						"distinct_resource_groups": 3, // 3 > 1
					},
				},
			},
			wantSafe: false,
		},
		{
			name: "F) Compliant identity => SAFE",
			identity: asset.CloudIdentity{
				ID: "role:compliant-role",
				Properties: map[string]any{
					"owner":   "team-e",
					"purpose": "single system access",
					"grants": map[string]any{
						"has_wildcard": false,
					},
					"scope": map[string]any{
						"distinct_systems":         1,
						"distinct_resource_groups": 1,
					},
				},
			},
			wantSafe: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isUnsafe := predicate.EvaluateIdentity(tt.identity, policy.ControlParams(params))
			gotSafe := !isUnsafe

			if gotSafe != tt.wantSafe {
				t.Errorf("identity %q: got safe=%v, want safe=%v", tt.identity.ID, gotSafe, tt.wantSafe)
			}
		})
	}
}

// TestMissingOperator tests the "missing" operator for various field types.
func TestMissingOperator(t *testing.T) {
	tests := []struct {
		name     string
		identity asset.CloudIdentity
		field    string
		wantMiss bool
	}{
		{
			name:     "nil owner is missing",
			identity: asset.CloudIdentity{ID: "test"},
			field:    "identity.owner",
			wantMiss: true,
		},
		{
			name:     "empty string owner is missing",
			identity: asset.CloudIdentity{ID: "test", Properties: map[string]any{"owner": ""}},
			field:    "identity.owner",
			wantMiss: true,
		},
		{
			name:     "non-empty owner is not missing",
			identity: asset.CloudIdentity{ID: "test", Properties: map[string]any{"owner": "team-a"}},
			field:    "identity.owner",
			wantMiss: false,
		},
		{
			name:     "nil purpose is missing",
			identity: asset.CloudIdentity{ID: "test"},
			field:    "identity.purpose",
			wantMiss: true,
		},
		{
			name:     "non-empty purpose is not missing",
			identity: asset.CloudIdentity{ID: "test", Properties: map[string]any{"purpose": "testing"}},
			field:    "identity.purpose",
			wantMiss: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "missing", Value: true}
			ctx := policy.NewIdentityEvalContext(tt.identity, nil)
			got := rule.MatchesWithContext(ctx)

			if got != tt.wantMiss {
				t.Errorf("missing check for %q: got %v, want %v", tt.field, got, tt.wantMiss)
			}
		})
	}
}

// TestGreaterThanOperator tests the "gt" operator.
func TestGreaterThanOperator(t *testing.T) {
	tests := []struct {
		name     string
		identity asset.CloudIdentity
		field    string
		param    string
		params   policy.ControlParams
		want     bool
	}{
		{
			name:     "2 > 1 is true",
			identity: asset.CloudIdentity{ID: "test", Properties: map[string]any{"scope": map[string]any{"distinct_systems": 2}}},
			field:    "identity.scope.distinct_systems",
			param:    "max_systems",
			params:   policy.ControlParams{"max_systems": 1},
			want:     true,
		},
		{
			name:     "1 > 1 is false",
			identity: asset.CloudIdentity{ID: "test", Properties: map[string]any{"scope": map[string]any{"distinct_systems": 1}}},
			field:    "identity.scope.distinct_systems",
			param:    "max_systems",
			params:   policy.ControlParams{"max_systems": 1},
			want:     false,
		},
		{
			name:     "0 > 1 is false",
			identity: asset.CloudIdentity{ID: "test", Properties: map[string]any{"scope": map[string]any{"distinct_systems": 0}}},
			field:    "identity.scope.distinct_systems",
			param:    "max_systems",
			params:   policy.ControlParams{"max_systems": 1},
			want:     false,
		},
		{
			name:     "3 > 2 (resource groups)",
			identity: asset.CloudIdentity{ID: "test", Properties: map[string]any{"scope": map[string]any{"distinct_resource_groups": 3}}},
			field:    "identity.scope.distinct_resource_groups",
			param:    "max_resource_groups",
			params:   policy.ControlParams{"max_resource_groups": 2},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{
				Field:          tt.field,
				Op:             "gt",
				ValueFromParam: tt.param,
			}
			ctx := policy.NewIdentityEvalContext(tt.identity, tt.params)
			got := rule.MatchesWithContext(ctx)

			if got != tt.want {
				t.Errorf("gt check: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNestedPredicates tests nested any/all predicates.
func TestNestedPredicates(t *testing.T) {
	// Test nested any (OR)
	t.Run("nested any - one matches", func(t *testing.T) {
		identity := asset.CloudIdentity{
			ID: "test",
			Properties: map[string]any{
				"purpose": "valid",
			},
		}
		rule := policy.PredicateRule{
			Any: []policy.PredicateRule{
				{Field: "identity.owner", Op: "missing", Value: true},
				{Field: "identity.purpose", Op: "missing", Value: true},
			},
		}
		ctx := policy.NewIdentityEvalContext(identity, nil)
		if !rule.MatchesWithContext(ctx) {
			t.Error("expected nested any to match when owner is missing")
		}
	})

	t.Run("nested any - none matches", func(t *testing.T) {
		identity := asset.CloudIdentity{
			ID: "test",
			Properties: map[string]any{
				"owner":   "team",
				"purpose": "valid",
			},
		}
		rule := policy.PredicateRule{
			Any: []policy.PredicateRule{
				{Field: "identity.owner", Op: "missing", Value: true},
				{Field: "identity.purpose", Op: "missing", Value: true},
			},
		}
		ctx := policy.NewIdentityEvalContext(identity, nil)
		if rule.MatchesWithContext(ctx) {
			t.Error("expected nested any to not match when both present")
		}
	})

	// Test nested all (AND)
	t.Run("nested all - both match", func(t *testing.T) {
		identity := asset.CloudIdentity{
			ID: "test",
			Properties: map[string]any{
				"grants": map[string]any{"has_wildcard": true},
			},
		}
		params := policy.ControlParams{"forbid_wildcards": true}
		rule := policy.PredicateRule{
			All: []policy.PredicateRule{
				{Field: "identity.grants.has_wildcard", Op: "eq", Value: true},
				{Field: "params.forbid_wildcards", Op: "eq", Value: true},
			},
		}
		ctx := policy.NewIdentityEvalContext(identity, params)
		if !rule.MatchesWithContext(ctx) {
			t.Error("expected nested all to match when both conditions true")
		}
	})

	t.Run("nested all - one fails", func(t *testing.T) {
		identity := asset.CloudIdentity{
			ID: "test",
			Properties: map[string]any{
				"grants": map[string]any{"has_wildcard": true},
			},
		}
		params := policy.ControlParams{"forbid_wildcards": false} // not forbidden
		rule := policy.PredicateRule{
			All: []policy.PredicateRule{
				{Field: "identity.grants.has_wildcard", Op: "eq", Value: true},
				{Field: "params.forbid_wildcards", Op: "eq", Value: true},
			},
		}
		ctx := policy.NewIdentityEvalContext(identity, params)
		if rule.MatchesWithContext(ctx) {
			t.Error("expected nested all to not match when forbid_wildcards=false")
		}
	})
}

// TestValueFromParam tests resolving values from control params.
func TestValueFromParam(t *testing.T) {
	identity := asset.CloudIdentity{
		ID: "test",
		Properties: map[string]any{
			"scope": map[string]any{
				"distinct_systems": 5,
			},
		},
	}
	params := policy.ControlParams{"max_systems": 3}

	rule := policy.PredicateRule{
		Field:          "identity.scope.distinct_systems",
		Op:             "gt",
		ValueFromParam: "max_systems",
	}

	ctx := policy.NewIdentityEvalContext(identity, params)
	if !rule.MatchesWithContext(ctx) {
		t.Error("expected 5 > 3 to be true via value_from_param")
	}

	// Test with lower value
	identity2 := asset.CloudIdentity{
		ID: "test2",
		Properties: map[string]any{
			"scope": map[string]any{
				"distinct_systems": 2,
			},
		},
	}
	ctx2 := policy.NewIdentityEvalContext(identity2, params)
	if rule.MatchesWithContext(ctx2) {
		t.Error("expected 2 > 3 to be false via value_from_param")
	}
}

// TestPresentOperator tests the "present" operator.
func TestPresentOperator(t *testing.T) {
	tests := []struct {
		name       string
		resource   asset.Asset
		field      string
		wantValue  bool
		wantResult bool
	}{
		{
			name: "present=true, field exists with value",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"business_justification": "approved for public access"},
			},
			field:      "properties.business_justification",
			wantValue:  true,
			wantResult: true,
		},
		{
			name: "present=true, field missing",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{},
			},
			field:      "properties.business_justification",
			wantValue:  true,
			wantResult: false,
		},
		{
			name: "present=true, field empty string",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"business_justification": ""},
			},
			field:      "properties.business_justification",
			wantValue:  true,
			wantResult: false,
		},
		{
			name: "present=true, field whitespace only",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"business_justification": "   "},
			},
			field:      "properties.business_justification",
			wantValue:  true,
			wantResult: false,
		},
		{
			name: "present=false, field missing => true (not present)",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{},
			},
			field:      "properties.business_justification",
			wantValue:  false,
			wantResult: true,
		},
		{
			name: "present=false, field exists => false (is present)",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"business_justification": "approved"},
			},
			field:      "properties.business_justification",
			wantValue:  false,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "present", Value: tt.wantValue}
			got := rule.Matches(tt.resource)
			if got != tt.wantResult {
				t.Errorf("present check: got %v, want %v", got, tt.wantResult)
			}
		})
	}
}

// TestInOperator tests the "in" operator.
func TestInOperator(t *testing.T) {
	tests := []struct {
		name     string
		resource asset.Asset
		field    string
		list     []any
		want     bool
	}{
		{
			name: "value in list",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"data_classification": "PII"},
			},
			field: "properties.data_classification",
			list:  []any{"PII", "PHI", "PCI"},
			want:  true,
		},
		{
			name: "value not in list",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"data_classification": "NONE"},
			},
			field: "properties.data_classification",
			list:  []any{"PII", "PHI", "PCI"},
			want:  false,
		},
		{
			name: "field missing",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{},
			},
			field: "properties.data_classification",
			list:  []any{"PII", "PHI", "PCI"},
			want:  false,
		},
		{
			name: "PHI in list",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"data_classification": "PHI"},
			},
			field: "properties.data_classification",
			list:  []any{"PII", "PHI", "PCI"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "in", Value: tt.list}
			got := rule.Matches(tt.resource)
			if got != tt.want {
				t.Errorf("in check: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestINVEXP001Predicate tests CTL.EXP.JUSTIFICATION.001 (Public Access Requires Business Justification).
func TestINVEXP001Predicate(t *testing.T) {
	predicate := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: "properties.public", Op: "eq", Value: true},
			{Field: "properties.business_justification", Op: "present", Value: false},
		},
	}

	tests := []struct {
		name     string
		resource asset.Asset
		want     bool
	}{
		{
			name: "public without justification => unsafe",
			resource: asset.Asset{
				ID:         "bucket-1",
				Properties: map[string]any{"public": true},
			},
			want: true,
		},
		{
			name: "public with justification => safe",
			resource: asset.Asset{
				ID:         "bucket-2",
				Properties: map[string]any{"public": true, "business_justification": "approved"},
			},
			want: false,
		},
		{
			name: "private without justification => safe",
			resource: asset.Asset{
				ID:         "bucket-3",
				Properties: map[string]any{"public": false},
			},
			want: false,
		},
		{
			name: "public with empty justification => unsafe",
			resource: asset.Asset{
				ID:         "bucket-4",
				Properties: map[string]any{"public": true, "business_justification": ""},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := predicate.Evaluate(tt.resource, nil)
			if got != tt.want {
				t.Errorf("CTL.EXP.JUSTIFICATION.001: got unsafe=%v, want unsafe=%v", got, tt.want)
			}
		})
	}
}

// TestINVEXP002Predicate tests CTL.EXP.STATE.001 (Sensitive Data Must Not Be Public).
func TestINVEXP002Predicate(t *testing.T) {
	predicate := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: "properties.public", Op: "eq", Value: true},
			{Field: "properties.data_classification", Op: "in", Value: []any{"PII", "PHI", "PCI"}},
		},
	}

	tests := []struct {
		name     string
		resource asset.Asset
		want     bool
	}{
		{
			name: "public with PII => unsafe",
			resource: asset.Asset{
				ID:         "bucket-1",
				Properties: map[string]any{"public": true, "data_classification": "PII"},
			},
			want: true,
		},
		{
			name: "public with PHI => unsafe",
			resource: asset.Asset{
				ID:         "bucket-2",
				Properties: map[string]any{"public": true, "data_classification": "PHI"},
			},
			want: true,
		},
		{
			name: "public with PCI => unsafe",
			resource: asset.Asset{
				ID:         "bucket-3",
				Properties: map[string]any{"public": true, "data_classification": "PCI"},
			},
			want: true,
		},
		{
			name: "public with NONE => safe",
			resource: asset.Asset{
				ID:         "bucket-4",
				Properties: map[string]any{"public": true, "data_classification": "NONE"},
			},
			want: false,
		},
		{
			name: "private with PII => safe",
			resource: asset.Asset{
				ID:         "bucket-5",
				Properties: map[string]any{"public": false, "data_classification": "PII"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := predicate.Evaluate(tt.resource, nil)
			if got != tt.want {
				t.Errorf("CTL.EXP.STATE.001: got unsafe=%v, want unsafe=%v", got, tt.want)
			}
		})
	}
}

// TestINVMETA001Predicate tests CTL.META.VISIBILITY.001 (Unknown Exposure Is Unsafe).
func TestINVMETA001Predicate(t *testing.T) {
	predicate := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: "properties.exposure_status", Op: "missing", Value: true},
			{Field: "properties.exposure_status", Op: "eq", Value: "unknown"},
		},
	}

	tests := []struct {
		name     string
		resource asset.Asset
		want     bool
	}{
		{
			name: "exposure_status missing => unsafe",
			resource: asset.Asset{
				ID:         "bucket-1",
				Properties: map[string]any{},
			},
			want: true,
		},
		{
			name: "exposure_status unknown => unsafe",
			resource: asset.Asset{
				ID:         "bucket-2",
				Properties: map[string]any{"exposure_status": "unknown"},
			},
			want: true,
		},
		{
			name: "exposure_status public => safe (known)",
			resource: asset.Asset{
				ID:         "bucket-3",
				Properties: map[string]any{"exposure_status": "public"},
			},
			want: false,
		},
		{
			name: "exposure_status private => safe (known)",
			resource: asset.Asset{
				ID:         "bucket-4",
				Properties: map[string]any{"exposure_status": "private"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := predicate.Evaluate(tt.resource, nil)
			if got != tt.want {
				t.Errorf("CTL.META.VISIBILITY.001: got unsafe=%v, want unsafe=%v", got, tt.want)
			}
		})
	}
}

// TestINVEXPOwnerMissing001Predicate tests CTL.EXP.OWNERSHIP.001 (Public Exposure Requires Owner).
func TestINVEXPOwnerMissing001Predicate(t *testing.T) {
	predicate := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: "properties.public", Op: "eq", Value: true},
			{Field: "properties.owner", Op: "missing", Value: true},
		},
	}

	tests := []struct {
		name     string
		resource asset.Asset
		want     bool
	}{
		{
			name: "public + missing owner => unsafe",
			resource: asset.Asset{
				ID:         "bucket-1",
				Properties: map[string]any{"public": true},
			},
			want: true,
		},
		{
			name: "public + owner present => safe",
			resource: asset.Asset{
				ID:         "bucket-2",
				Properties: map[string]any{"public": true, "owner": "team-security"},
			},
			want: false,
		},
		{
			name: "private + missing owner => safe",
			resource: asset.Asset{
				ID:         "bucket-3",
				Properties: map[string]any{"public": false},
			},
			want: false,
		},
		{
			name: "public + empty owner => unsafe",
			resource: asset.Asset{
				ID:         "bucket-4",
				Properties: map[string]any{"public": true, "owner": ""},
			},
			want: true,
		},
		{
			name: "public + whitespace owner => unsafe",
			resource: asset.Asset{
				ID:         "bucket-5",
				Properties: map[string]any{"public": true, "owner": "   "},
			},
			want: true,
		},
		{
			name: "private + owner present => safe",
			resource: asset.Asset{
				ID:         "bucket-6",
				Properties: map[string]any{"public": false, "owner": "team-data"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := predicate.Evaluate(tt.resource, nil)
			if got != tt.want {
				t.Errorf("CTL.EXP.OWNERSHIP.001: got unsafe=%v, want unsafe=%v", got, tt.want)
			}
		})
	}
}

// TestListEmptyOperator tests the "list_empty" operator.
func TestListEmptyOperator(t *testing.T) {
	tests := []struct {
		name     string
		resource asset.Asset
		field    string
		wantVal  bool
		want     bool
	}{
		{
			name: "empty list matches list_empty=true",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"audience": []any{}},
			},
			field:   "properties.audience",
			wantVal: true,
			want:    true,
		},
		{
			name: "non-empty list does not match list_empty=true",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"audience": []any{"alice@company.com"}},
			},
			field:   "properties.audience",
			wantVal: true,
			want:    false,
		},
		{
			name: "missing field matches list_empty=true",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{},
			},
			field:   "properties.audience",
			wantVal: true,
			want:    true,
		},
		{
			name: "nil field matches list_empty=true",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"audience": nil},
			},
			field:   "properties.audience",
			wantVal: true,
			want:    true,
		},
		{
			name: "non-list value (string) matches list_empty=true",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"audience": "not-a-list"},
			},
			field:   "properties.audience",
			wantVal: true,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "list_empty", Value: tt.wantVal}
			got := rule.Matches(tt.resource)
			if got != tt.want {
				t.Errorf("list_empty: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNotSubsetOfFieldOperator tests the "not_subset_of_field" operator.
func TestNotSubsetOfFieldOperator(t *testing.T) {
	tests := []struct {
		name     string
		resource asset.Asset
		field    string
		other    string
		want     bool
	}{
		{
			name: "actual contains extra recipient => true",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"intended_audience": []any{"alice@company.com", "bob@company.com"},
					"actual_audience":   []any{"alice@company.com", "bob@company.com", "eve@attacker.com"},
				},
			},
			field: "properties.actual_audience",
			other: "properties.intended_audience",
			want:  true,
		},
		{
			name: "actual equals intended => false",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"intended_audience": []any{"alice@company.com", "bob@company.com"},
					"actual_audience":   []any{"alice@company.com", "bob@company.com"},
				},
			},
			field: "properties.actual_audience",
			other: "properties.intended_audience",
			want:  false,
		},
		{
			name: "actual is subset of intended => false",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"intended_audience": []any{"alice@company.com", "bob@company.com", "charlie@company.com"},
					"actual_audience":   []any{"alice@company.com"},
				},
			},
			field: "properties.actual_audience",
			other: "properties.intended_audience",
			want:  false,
		},
		{
			name: "intended missing => actual has extra elements",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"actual_audience": []any{"alice@company.com"},
				},
			},
			field: "properties.actual_audience",
			other: "properties.intended_audience",
			want:  true,
		},
		{
			name: "actual missing => false (field doesn't exist)",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"intended_audience": []any{"alice@company.com"},
				},
			},
			field: "properties.actual_audience",
			other: "properties.intended_audience",
			want:  false,
		},
		{
			name: "empty actual with non-empty intended => false (empty is subset of anything)",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"intended_audience": []any{"alice@company.com"},
					"actual_audience":   []any{},
				},
			},
			field: "properties.actual_audience",
			other: "properties.intended_audience",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "not_subset_of_field", Value: tt.other}
			got := rule.Matches(tt.resource)
			if got != tt.want {
				t.Errorf("not_subset_of_field: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNotSubsetOfFieldAgainstParams tests not_subset_of_field with params.* paths.
func TestNotSubsetOfFieldAgainstParams(t *testing.T) {
	rule := policy.PredicateRule{
		Field: "properties.storage.access.external_account_ids",
		Op:    "not_subset_of_field",
		Value: "params.allowed_accounts",
	}

	t.Run("all external accounts are allowlisted => false", func(t *testing.T) {
		resource := asset.Asset{
			ID: "bucket-1",
			Properties: map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"external_account_ids": []any{"111122223333"},
					},
				},
			},
		}
		params := policy.ControlParams{
			"allowed_accounts": []any{"111122223333", "444455556666"},
		}

		ctx := policy.NewAssetEvalContext(resource, params)
		if got := rule.MatchesWithContext(ctx); got {
			t.Error("expected false when all external accounts are in params.allowed_accounts")
		}
	})

	t.Run("one external account is outside allowlist => true", func(t *testing.T) {
		resource := asset.Asset{
			ID: "bucket-2",
			Properties: map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"external_account_ids": []any{"111122223333", "999988887777"},
					},
				},
			},
		}
		params := policy.ControlParams{
			"allowed_accounts": []any{"111122223333"},
		}

		ctx := policy.NewAssetEvalContext(resource, params)
		if got := rule.MatchesWithContext(ctx); !got {
			t.Error("expected true when any external account is not in params.allowed_accounts")
		}
	})
}

// TestNeqFieldOperator tests the "neq_field" operator.
func TestNeqFieldOperator(t *testing.T) {
	tests := []struct {
		name     string
		resource asset.Asset
		field    string
		other    string
		want     bool
	}{
		{
			name: "fields are equal => false",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"actor_subject_id": "patient:alice",
					"subject_id":       "patient:alice",
				},
			},
			field: "properties.actor_subject_id",
			other: "properties.subject_id",
			want:  false,
		},
		{
			name: "fields are not equal => true",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"actor_subject_id": "patient:bob",
					"subject_id":       "patient:alice",
				},
			},
			field: "properties.actor_subject_id",
			other: "properties.subject_id",
			want:  true,
		},
		{
			name: "other field missing => true (not equal)",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"actor_subject_id": "patient:bob",
				},
			},
			field: "properties.actor_subject_id",
			other: "properties.subject_id",
			want:  true,
		},
		{
			name: "main field missing => false",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"subject_id": "patient:alice",
				},
			},
			field: "properties.actor_subject_id",
			other: "properties.subject_id",
			want:  false,
		},
		{
			name: "numeric fields equal => false",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"field_a": 42,
					"field_b": 42,
				},
			},
			field: "properties.field_a",
			other: "properties.field_b",
			want:  false,
		},
		{
			name: "numeric fields not equal => true",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"field_a": 42,
					"field_b": 99,
				},
			},
			field: "properties.field_a",
			other: "properties.field_b",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "neq_field", Value: tt.other}
			got := rule.Matches(tt.resource)
			if got != tt.want {
				t.Errorf("neq_field: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNotInFieldOperator tests the "not_in_field" operator.
func TestNotInFieldOperator(t *testing.T) {
	tests := []struct {
		name     string
		resource asset.Asset
		field    string
		listPath string
		want     bool
	}{
		{
			name: "value in list => false",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"subject_id":       "patient:alice",
					"allowed_subjects": []any{"patient:alice", "patient:bob"},
				},
			},
			field:    "properties.subject_id",
			listPath: "properties.allowed_subjects",
			want:     false,
		},
		{
			name: "value not in list => true",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"subject_id":       "patient:eve",
					"allowed_subjects": []any{"patient:alice", "patient:bob"},
				},
			},
			field:    "properties.subject_id",
			listPath: "properties.allowed_subjects",
			want:     true,
		},
		{
			name: "list missing => true (not in non-existent list)",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"subject_id": "patient:alice",
				},
			},
			field:    "properties.subject_id",
			listPath: "properties.allowed_subjects",
			want:     true,
		},
		{
			name: "value field missing => true",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"allowed_subjects": []any{"patient:alice", "patient:bob"},
				},
			},
			field:    "properties.subject_id",
			listPath: "properties.allowed_subjects",
			want:     true,
		},
		{
			name: "empty list => true (not in empty list)",
			resource: asset.Asset{
				ID: "test",
				Properties: map[string]any{
					"subject_id":       "patient:alice",
					"allowed_subjects": []any{},
				},
			},
			field:    "properties.subject_id",
			listPath: "properties.allowed_subjects",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "not_in_field", Value: tt.listPath}
			got := rule.Matches(tt.resource)
			if got != tt.want {
				t.Errorf("not_in_field: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestContainsOperator tests the "contains" operator.
func TestContainsOperator(t *testing.T) {
	tests := []struct {
		name     string
		resource asset.Asset
		field    string
		value    string
		want     bool
	}{
		{
			name: "field contains substring => true",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"purpose": "signs_downloads;enforce_prefix=false"},
			},
			field: "properties.purpose",
			value: "enforce_prefix=false",
			want:  true,
		},
		{
			name: "field does not contain substring => false",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{"purpose": "signs_downloads;enforce_prefix=true"},
			},
			field: "properties.purpose",
			value: "enforce_prefix=false",
			want:  false,
		},
		{
			name: "field missing => false",
			resource: asset.Asset{
				ID:         "test",
				Properties: map[string]any{},
			},
			field: "properties.purpose",
			value: "enforce_prefix=false",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := policy.PredicateRule{Field: tt.field, Op: "contains", Value: tt.value}
			got := rule.Matches(tt.resource)
			if got != tt.want {
				t.Errorf("contains: got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAnyMatchOperator tests the "any_match" operator.
func TestAnyMatchOperator(t *testing.T) {
	t.Run("identity matches nested predicate", func(t *testing.T) {
		ctx := policy.EvalContext{
			Properties: map[string]any{
				"storage": map[string]any{"kind": "bucket"},
			},
			Identities: []asset.CloudIdentity{
				{
					ID:     "appsigner:s3:safe",
					Type:   kernel.AssetType("app_signer"),
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"purpose": "signs_downloads;enforce_prefix=true;allow_traversal=false",
					},
				},
				{
					ID:     "appsigner:s3:unsafe",
					Type:   kernel.AssetType("app_signer"),
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"purpose": "signs_downloads;enforce_prefix=false;allow_traversal=true",
					},
				},
			},
			PredicateParser: yamlPredicateParser,
		}

		// Nested predicate: type == "app_signer" AND purpose contains "allow_traversal=true"
		rule := policy.PredicateRule{
			Field: "identities",
			Op:    "any_match",
			Value: map[string]any{
				"all": []any{
					map[string]any{"field": "type", "op": "eq", "value": "app_signer"},
					map[string]any{"field": "purpose", "op": "contains", "value": "allow_traversal=true"},
				},
			},
		}

		got := rule.MatchesWithContext(ctx)
		if !got {
			t.Error("expected any_match to find unsafe identity")
		}
	})

	t.Run("no identity matches", func(t *testing.T) {
		ctx := policy.EvalContext{
			Properties: map[string]any{},
			Identities: []asset.CloudIdentity{
				{
					ID:     "appsigner:s3:safe",
					Type:   kernel.AssetType("app_signer"),
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"purpose": "signs_downloads;enforce_prefix=true;allow_traversal=false",
					},
				},
			},
			PredicateParser: yamlPredicateParser,
		}

		rule := policy.PredicateRule{
			Field: "identities",
			Op:    "any_match",
			Value: map[string]any{
				"all": []any{
					map[string]any{"field": "type", "op": "eq", "value": "app_signer"},
					map[string]any{"field": "purpose", "op": "contains", "value": "allow_traversal=true"},
				},
			},
		}

		got := rule.MatchesWithContext(ctx)
		if got {
			t.Error("expected any_match to NOT match when no identity is unsafe")
		}
	})

	t.Run("empty identities", func(t *testing.T) {
		ctx := policy.EvalContext{
			Properties: map[string]any{},
			Identities: []asset.CloudIdentity{},
		}

		rule := policy.PredicateRule{
			Field: "identities",
			Op:    "any_match",
			Value: map[string]any{
				"any": []any{
					map[string]any{"field": "type", "op": "eq", "value": "app_signer"},
				},
			},
		}

		got := rule.MatchesWithContext(ctx)
		if got {
			t.Error("expected any_match to return false on empty identities")
		}
	})

	t.Run("nil identities field => false", func(t *testing.T) {
		ctx := policy.EvalContext{
			Properties: map[string]any{},
		}

		rule := policy.PredicateRule{
			Field: "identities",
			Op:    "any_match",
			Value: map[string]any{
				"any": []any{
					map[string]any{"field": "type", "op": "eq", "value": "app_signer"},
				},
			},
		}

		got := rule.MatchesWithContext(ctx)
		if got {
			t.Error("expected any_match to return false when identities is nil")
		}
	})

	t.Run("nested all/any combined", func(t *testing.T) {
		ctx := policy.EvalContext{
			Properties: map[string]any{},
			Identities: []asset.CloudIdentity{
				{
					ID:     "appsigner:s3:vuln",
					Type:   kernel.AssetType("app_signer"),
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"purpose": "signs_downloads;enforce_prefix=false;allow_traversal=true",
					},
				},
			},
			PredicateParser: yamlPredicateParser,
		}

		// Nested: type == "app_signer" AND (purpose contains "allow_traversal=true" OR purpose contains "enforce_prefix=false")
		rule := policy.PredicateRule{
			Field: "identities",
			Op:    "any_match",
			Value: map[string]any{
				"all": []any{
					map[string]any{"field": "type", "op": "eq", "value": "app_signer"},
					map[string]any{
						"any": []any{
							map[string]any{"field": "purpose", "op": "contains", "value": "allow_traversal=true"},
							map[string]any{"field": "purpose", "op": "contains", "value": "enforce_prefix=false"},
						},
					},
				},
			},
		}

		got := rule.MatchesWithContext(ctx)
		if !got {
			t.Error("expected nested all/any to match unsafe identity")
		}
	})
}
