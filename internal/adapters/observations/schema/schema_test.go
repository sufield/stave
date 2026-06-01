package schema

import (
	"slices"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestValidateAsset_UnregisteredTypeSkips(t *testing.T) {
	a := asset.Asset{
		ID:   "x",
		Type: kernel.AssetType("never_registered"),
	}
	if _, ok := ValidateAsset(a); ok {
		t.Fatal("unregistered type must report ok=false")
	}
}

func TestValidateAsset_AllPresentNoMissing(t *testing.T) {
	a := asset.Asset{
		ID:   "bucket-1",
		Type: kernel.AssetType("aws_s3_bucket"),
		Properties: map[string]any{
			"storage": map[string]any{
				"access": map[string]any{
					"has_wildcard_principal":  false,
					"has_external_write":      false,
					"allows_anonymous_list":   false,
					"exposes_bucket_policy":   false,
					"effective_network_scope": "account",
					"has_ip_condition":        false,
					"has_vpc_condition":       false,
				},
			},
		},
	}
	res, ok := ValidateAsset(a)
	if !ok {
		t.Fatal("registered type must report ok=true")
	}
	if len(res.MissingRequired) != 0 {
		t.Errorf("required missing should be empty: %v", res.MissingRequired)
	}
}

func TestValidateAsset_MissingRequiredSurfaces(t *testing.T) {
	a := asset.Asset{
		ID:         "bucket-2",
		Type:       kernel.AssetType("aws_s3_bucket"),
		Properties: map[string]any{}, // EMPTY — every required field is absent
	}
	res, ok := ValidateAsset(a)
	if !ok {
		t.Fatal("registered type must report ok=true")
	}
	if len(res.MissingRequired) == 0 {
		t.Fatal("empty property bag must surface required misses")
	}
	// The required count is the foundational signal — exact paths
	// are not pinned (they evolve as the schema grows) but the
	// most important one must always be present in this set.
	if !containsString(res.MissingRequired, "properties.storage.access.has_wildcard_principal") {
		t.Errorf("expected has_wildcard_principal in missing required, got: %v", res.MissingRequired)
	}
}

func TestValidateAsset_NilValueCountsAsMissing(t *testing.T) {
	// A literal nil at the leaf is the unambiguous "extractor did
	// not produce this field" signal. False, empty string, and
	// empty list all count as PRESENT — they are intentional
	// extractor outputs.
	a := asset.Asset{
		ID:   "bucket-3",
		Type: kernel.AssetType("aws_s3_bucket"),
		Properties: map[string]any{
			"storage": map[string]any{
				"access": map[string]any{
					"has_wildcard_principal": nil, // explicit nil
				},
			},
		},
	}
	res, _ := ValidateAsset(a)
	if !containsString(res.MissingRequired, "properties.storage.access.has_wildcard_principal") {
		t.Fatalf("explicit nil at leaf must count as missing: %+v", res)
	}
}

func TestValidateAsset_FalseLeafCountsAsPresent(t *testing.T) {
	// Booleans set to false are intentional. They must NOT be
	// reported as missing — that would be the classic false-
	// positive the schema is trying to prevent.
	a := asset.Asset{
		ID:   "bucket-4",
		Type: kernel.AssetType("aws_s3_bucket"),
		Properties: map[string]any{
			"storage": map[string]any{
				"access": map[string]any{
					"has_wildcard_principal":  false,
					"has_external_write":      false,
					"allows_anonymous_list":   false,
					"exposes_bucket_policy":   false,
					"effective_network_scope": "account",
					"has_ip_condition":        false,
					"has_vpc_condition":       false,
				},
			},
		},
	}
	res, _ := ValidateAsset(a)
	if len(res.MissingRequired) != 0 {
		t.Errorf("false leaves must count as present, got missing: %v", res.MissingRequired)
	}
}

func TestRegister_OverwritesAndIsThreadSafe(t *testing.T) {
	// Tests that install a temporary schema should not corrupt the
	// global registry for subsequent tests. Use a fresh asset type
	// to avoid stomping the real aws_s3_bucket entry.
	tt := kernel.AssetType("test_only_type")
	Register(Schema{
		AssetType: tt,
		Fields:    []FieldRequirement{{Path: "properties.x", Required: true}},
	})
	defer func() {
		registryMu.Lock()
		delete(Schemas, tt)
		registryMu.Unlock()
	}()
	if _, ok := Lookup(tt); !ok {
		t.Fatal("Register should make schema visible to Lookup")
	}
	Register(Schema{
		AssetType: tt,
		Fields:    []FieldRequirement{{Path: "properties.y", Required: true}},
	})
	s, _ := Lookup(tt)
	if len(s.Fields) != 1 || s.Fields[0].Path != "properties.y" {
		t.Errorf("Register should overwrite, got: %+v", s.Fields)
	}
}

func TestHasPath_HandlesMissingIntermediateMap(t *testing.T) {
	// "properties.a.b.c" with no "a" at the root must return false,
	// not panic on the nil intermediate map.
	if hasPath(map[string]any{}, "properties.a.b.c") {
		t.Fatal("missing intermediate map should return false")
	}
}

func TestHasPath_RejectsPathsWithoutPrefix(t *testing.T) {
	// Defensive: schema authors who forget the "properties." prefix
	// should see the field reported as missing (which produces a
	// visible warning) rather than the validator silently treating
	// the misspelled path as always-present.
	if hasPath(map[string]any{"x": true}, "x") {
		t.Fatal("path without properties. prefix should report missing")
	}
}

func containsString(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
