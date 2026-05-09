package risk

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

// TestNewScopeResolverFromSnapshots_ResolvesNestedString walks a
// realistic Cognito user-pool fixture and confirms the resolver
// returns the user_pool_id value at the catalog's natural property
// path.
func TestNewScopeResolverFromSnapshots_ResolvesNestedString(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{{
			ID: "arn:aws:cognito-idp:us-east-1:111122223333:userpool/u1",
			Properties: map[string]any{
				"identity": map[string]any{
					"cognito": map[string]any{
						"user_pool_id": "u1",
					},
				},
			},
		}},
	}
	r := NewScopeResolverFromSnapshots([]asset.Snapshot{snap})
	v, ok := r("arn:aws:cognito-idp:us-east-1:111122223333:userpool/u1", "properties.identity.cognito.user_pool_id")
	if !ok {
		t.Fatal("resolver returned ok=false")
	}
	if v != "u1" {
		t.Errorf("v = %q, want u1", v)
	}
}

// TestNewScopeResolverFromSnapshots_PropertiesPrefixOptional
// confirms the leading "properties." segment can be omitted —
// callers can write paths in either form.
func TestNewScopeResolverFromSnapshots_PropertiesPrefixOptional(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{{
			ID:         "a-1",
			Properties: map[string]any{"foo": map[string]any{"bar": "baz"}},
		}},
	}
	r := NewScopeResolverFromSnapshots([]asset.Snapshot{snap})
	v1, ok1 := r("a-1", "properties.foo.bar")
	v2, ok2 := r("a-1", "foo.bar")
	if !ok1 || v1 != "baz" {
		t.Errorf("with prefix: %q ok=%v", v1, ok1)
	}
	if !ok2 || v2 != "baz" {
		t.Errorf("without prefix: %q ok=%v", v2, ok2)
	}
}

// TestNewScopeResolverFromSnapshots_UnknownAsset returns false so
// the chain engine falls back to asset.ID grouping for that pair.
func TestNewScopeResolverFromSnapshots_UnknownAsset(t *testing.T) {
	r := NewScopeResolverFromSnapshots(nil)
	if _, ok := r("missing", "properties.x"); ok {
		t.Fatal("expected ok=false for unknown asset")
	}
}

// TestNewScopeResolverFromSnapshots_NonScalarLeafFails ensures map
// and slice leaves don't surface as scope keys — chain grouping
// requires scalars.
func TestNewScopeResolverFromSnapshots_NonScalarLeafFails(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{{
			ID: "a-1",
			Properties: map[string]any{
				"map":   map[string]any{"k": "v"},
				"slice": []any{"x", "y"},
				"empty": "",
			},
		}},
	}
	r := NewScopeResolverFromSnapshots([]asset.Snapshot{snap})
	if _, ok := r("a-1", "properties.map"); ok {
		t.Error("map leaf should return false")
	}
	if _, ok := r("a-1", "properties.slice"); ok {
		t.Error("slice leaf should return false")
	}
	if _, ok := r("a-1", "properties.empty"); ok {
		t.Error("empty string leaf should return false")
	}
}

// TestNewScopeResolverFromSnapshots_ScalarTypes confirms bool,
// int, and float values render to their canonical string forms.
func TestNewScopeResolverFromSnapshots_ScalarTypes(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{{
			ID: "a-1",
			Properties: map[string]any{
				"b_true":  true,
				"b_false": false,
				"i":       42,
				"f":       3.14,
			},
		}},
	}
	r := NewScopeResolverFromSnapshots([]asset.Snapshot{snap})
	cases := map[string]string{
		"properties.b_true":  "true",
		"properties.b_false": "false",
		"properties.i":       "42",
		"properties.f":       "3.14",
	}
	for path, want := range cases {
		got, ok := r("a-1", path)
		if !ok || got != want {
			t.Errorf("path %q: got=%q ok=%v want=%q", path, got, ok, want)
		}
	}
}

// TestNewScopeResolverFromSnapshots_IdentitiesIncluded confirms
// CloudIdentity assets (the IAM-side ledger) participate in
// resolution alongside regular Asset entries, since chain
// scope_field can target either kind of asset.
func TestNewScopeResolverFromSnapshots_IdentitiesIncluded(t *testing.T) {
	snap := asset.Snapshot{
		Identities: []asset.CloudIdentity{{
			ID:         "arn:aws:iam::111122223333:role/AppRole",
			Properties: map[string]any{"identity": map[string]any{"name": "AppRole"}},
		}},
	}
	r := NewScopeResolverFromSnapshots([]asset.Snapshot{snap})
	v, ok := r("arn:aws:iam::111122223333:role/AppRole", "properties.identity.name")
	if !ok || v != "AppRole" {
		t.Errorf("identity lookup: got=%q ok=%v want=AppRole", v, ok)
	}
}
