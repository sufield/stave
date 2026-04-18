package derive

import (
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func bucket(id, name string, extras map[string]any) asset.Asset {
	storage := map[string]any{
		"kind": "bucket",
		"name": name,
	}
	maps.Copy(storage, extras)
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": storage,
		},
	}
}

func accessPoint(id, name, bucketName string, policyPublic, pabFullyBlocked bool) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_access_point"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": map[string]any{
				"kind":                        "access_point",
				"name":                        name,
				"bucket_name":                 bucketName,
				"policy_is_public":            policyPublic,
				"public_access_fully_blocked": pabFullyBlocked,
			},
		},
	}
}

func snapshotOf(assets ...asset.Asset) asset.Snapshot {
	return asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		CapturedAt:    time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
		Assets:        assets,
	}
}

// exposureOf extracts the derived storage.exposure.* subtree from a bucket
// asset, returning nil when absent.
func exposureOf(a asset.Asset) map[string]any {
	storage, _ := a.Properties["storage"].(map[string]any)
	exposure, _ := storage["exposure"].(map[string]any)
	return exposure
}

func TestDerivation_BucketAPExposure_NoAccessPoints(t *testing.T) {
	in := []asset.Snapshot{
		snapshotOf(bucket("b1", "my-bucket", nil)),
	}
	out := EnrichBucketAPExposure(in)
	if exposureOf(out[0].Assets[0]) != nil {
		t.Error("expected no storage.exposure field on bucket with no APs")
	}
}

func TestDerivation_BucketAPExposure_OnePublicAP(t *testing.T) {
	in := []asset.Snapshot{
		snapshotOf(
			bucket("b1", "my-bucket", nil),
			accessPoint("ap1", "leaky", "my-bucket", true, true), // policy_is_public=true
		),
	}
	out := EnrichBucketAPExposure(in)

	exp := exposureOf(out[0].Assets[0])
	if exp == nil {
		t.Fatal("expected storage.exposure to be populated on the bucket")
	}
	if got := exp["has_public_access_point"]; got != true {
		t.Errorf("has_public_access_point = %v, want true", got)
	}
	want := []any{"leaky"}
	if got := exp["public_access_point_names"]; !reflect.DeepEqual(got, want) {
		t.Errorf("public_access_point_names = %v, want %v", got, want)
	}
}

func TestDerivation_BucketAPExposure_MultipleAPsOnePublic(t *testing.T) {
	in := []asset.Snapshot{
		snapshotOf(
			bucket("b1", "my-bucket", nil),
			accessPoint("ap-clean", "zeta-clean", "my-bucket", false, true),
			accessPoint("ap-leaky", "alpha-leaky", "my-bucket", true, true),
			accessPoint("ap-pab-off", "mu-pab-off", "my-bucket", false, false),
		),
	}
	out := EnrichBucketAPExposure(in)

	exp := exposureOf(out[0].Assets[0])
	if exp == nil {
		t.Fatal("expected storage.exposure to be populated")
	}
	want := []any{"alpha-leaky", "mu-pab-off"} // sorted; zeta-clean excluded
	if got := exp["public_access_point_names"]; !reflect.DeepEqual(got, want) {
		t.Errorf("public_access_point_names = %v, want %v (only non-clean APs, sorted)", got, want)
	}
}

func TestDerivation_BucketAPExposure_APReferencesDifferentBucket(t *testing.T) {
	in := []asset.Snapshot{
		snapshotOf(
			bucket("b1", "my-bucket", nil),
			accessPoint("ap1", "elsewhere-ap", "other-bucket", true, true),
		),
	}
	out := EnrichBucketAPExposure(in)
	if exposureOf(out[0].Assets[0]) != nil {
		t.Error("expected no exposure on my-bucket — the public AP targets other-bucket")
	}
}

func TestDerivation_BucketAPExposure_RawSnapshotsNotMutated(t *testing.T) {
	ap := accessPoint("ap1", "leaky", "my-bucket", true, true)
	b := bucket("b1", "my-bucket", nil)
	in := []asset.Snapshot{snapshotOf(b, ap)}

	_ = EnrichBucketAPExposure(in)

	// The raw bucket's Properties must not have been mutated.
	rawStorage := in[0].Assets[0].Properties["storage"].(map[string]any)
	if _, ok := rawStorage["exposure"]; ok {
		t.Error("raw snapshot mutated — storage.exposure appeared on the input bucket")
	}
}

func TestDerivation_BucketAPExposure_Idempotent(t *testing.T) {
	in := []asset.Snapshot{
		snapshotOf(
			bucket("b1", "my-bucket", nil),
			accessPoint("ap1", "leaky", "my-bucket", true, true),
		),
	}
	once := EnrichBucketAPExposure(in)
	twice := EnrichBucketAPExposure(once)

	if !reflect.DeepEqual(exposureOf(once[0].Assets[0]), exposureOf(twice[0].Assets[0])) {
		t.Error("derivation is not idempotent — second run produced a different exposure field")
	}
}

func TestDerivation_BucketAPExposure_CrossSnapshotIsolation(t *testing.T) {
	// A public AP in snapshot t0 must NOT join with a bucket in snapshot t1.
	// Each snapshot is an independent point-in-time; cross-snapshot joins
	// are a separate design decision and are deliberately not performed.
	snap0 := asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		CapturedAt:    time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			accessPoint("ap1", "leaky", "my-bucket", true, true),
		},
	}
	snap1 := asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		CapturedAt:    time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			bucket("b1", "my-bucket", nil),
		},
	}

	out := EnrichBucketAPExposure([]asset.Snapshot{snap0, snap1})
	if exposureOf(out[1].Assets[0]) != nil {
		t.Error("bucket in snap1 should not be enriched by an AP that lives in snap0")
	}
}
