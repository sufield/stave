package sirfacts

import (
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
	"github.com/sufield/stave/internal/core/sir"
)

// readingCtl is the minimal control shape AutoPropertyFacts needs:
// applicable to one asset type and reading one property path. We
// hand-build the predicate node because the YAML loader is the
// path most tests use, but importing yaml just to build a single
// predicate would tangle test deps.
func readingCtl(id, assetType, path string) policy.ControlDefinition {
	return policy.ControlDefinition{
		ID:                   kernel.ControlID(id),
		ApplicableAssetTypes: []kernel.AssetType{kernel.AssetType(assetType)},
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath(path), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
	}
}

// TestAutoPropertyFacts_EmitsForObservedScalars verifies the
// happy path: an asset of type T, a control reading
// properties.X.Y on T, and an observation that carries a scalar
// at properties.X.Y all combine to emit one auto_prop_x_y triple.
func TestAutoPropertyFacts_EmitsForObservedScalars(t *testing.T) {
	controls := []policy.ControlDefinition{
		readingCtl("CTL.001", "aws_s3_bucket", "properties.storage.access.public_read"),
	}
	assets := []sir.AssetFact{
		{
			ID:   "arn:aws:s3:::test",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"public_read": true,
					},
				},
			},
		},
	}
	facts := AutoPropertyFacts(assets, controls)
	if len(facts) != 1 {
		t.Fatalf("want 1 fact, got %d: %+v", len(facts), facts)
	}
	got := facts[0]
	wantPred := "auto_prop_storage_access_public_read"
	if got.Predicate != wantPred {
		t.Errorf("Predicate: got %q, want %q", got.Predicate, wantPred)
	}
	if got.Subject != "arn:aws:s3:::test" {
		t.Errorf("Subject: got %q", got.Subject)
	}
	if got.Object != "true" {
		t.Errorf("Object: got %q, want \"true\"", got.Object)
	}
	if got.Source != "auto_property" {
		t.Errorf("Source: got %q, want auto_property", got.Source)
	}
}

// TestAutoPropertyFacts_NoEmissionForUnpopulatedPath confirms the
// observation-side cutoff: when the catalog reads a path but the
// snapshot does not carry a value there, no fact is emitted. This
// is the closed-world default — absence does not equal `false`.
// Without this rule, the auto-projector would invent triples for
// every catalog path on every asset and the experiment's growth
// number would be meaningless.
func TestAutoPropertyFacts_NoEmissionForUnpopulatedPath(t *testing.T) {
	controls := []policy.ControlDefinition{
		readingCtl("CTL.001", "aws_s3_bucket", "properties.storage.access.public_read"),
	}
	assets := []sir.AssetFact{
		{
			ID:         "arn:aws:s3:::sparse",
			Type:       "aws_s3_bucket",
			Properties: map[string]any{},
		},
	}
	if facts := AutoPropertyFacts(assets, controls); len(facts) != 0 {
		t.Errorf("expected no facts for unpopulated path; got %+v", facts)
	}
}

// TestAutoPropertyFacts_SkipsNonScalarLeaves asserts the same
// scalar-only rule the curated propertyFacts walker uses: a map
// or slice at the leaf produces no fact. Without this the
// projector would dump opaque map[...]any{} as a string object
// and any solver consuming it would fail to parse the value.
func TestAutoPropertyFacts_SkipsNonScalarLeaves(t *testing.T) {
	controls := []policy.ControlDefinition{
		readingCtl("CTL.001", "aws_s3_bucket", "properties.storage.tags"),
	}
	assets := []sir.AssetFact{
		{
			ID:   "arn:aws:s3:::map-leaf",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"storage": map[string]any{
					"tags": map[string]any{"data-classification": "phi"},
				},
			},
		},
	}
	if facts := AutoPropertyFacts(assets, controls); len(facts) != 0 {
		t.Errorf("expected no facts for map leaf; got %+v", facts)
	}
}

// TestAutoPropertyFacts_AssetTypeFilter confirms the projector
// only walks paths whose declaring control names the asset's
// type in applicable_asset_types. A control reading
// properties.identity.kind on aws_iam_role does not emit a fact
// against an aws_s3_bucket asset even if the bucket happens to
// carry a properties.identity.kind value.
func TestAutoPropertyFacts_AssetTypeFilter(t *testing.T) {
	controls := []policy.ControlDefinition{
		readingCtl("CTL.001", "aws_iam_role", "properties.identity.kind"),
	}
	assets := []sir.AssetFact{
		{
			ID:   "arn:aws:s3:::mismatched",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"identity": map[string]any{"kind": "iam_role"},
			},
		},
	}
	if facts := AutoPropertyFacts(assets, controls); len(facts) != 0 {
		t.Errorf("expected no facts when asset type doesn't match control's applicable types; got %+v", facts)
	}
}

// TestSanitizeAutoPredicate locks in the predicate-name encoding.
// SMT-LIB tolerates lowercase letters, digits, and underscores
// in unquoted identifiers. Anything else — uppercase, hyphens,
// the leading "properties." namespace — gets normalised here so
// downstream parsers never need to escape the predicate name.
func TestSanitizeAutoPredicate(t *testing.T) {
	cases := map[string]string{
		"properties.storage.access.public_read":          "storage_access_public_read",
		"properties.storage.tags.data-classification":    "storage_tags_data_classification",
		"properties.identity.cognito.unauth_role_has_s3": "identity_cognito_unauth_role_has_s3",
		// uppercase + special chars collapse
		"properties.AWS::SomeProperty": "aws_someproperty",
	}
	for in, want := range cases {
		got := sanitizeAutoPredicate(in)
		if got != want {
			t.Errorf("sanitize(%q): got %q, want %q", in, got, want)
		}
	}
	// No leading or trailing underscores.
	if strings.HasPrefix(sanitizeAutoPredicate("properties.X"), "_") {
		t.Error("predicate name must not start with underscore")
	}
}
