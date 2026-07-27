package derive

import (
	"slices"

	"github.com/sufield/stave/internal/core/asset"
)

func bucketType() string      { return BucketAPTypes.Bucket }
func accessPointType() string { return BucketAPTypes.AccessPoint }

// EnrichBucketAPExposure attaches two derived fields to every bucket asset
// that has at least one public-reaching access point in the same snapshot
// targeting it. The asset types it matches are configured via BucketAPTypes
// (set by the provider at startup).
//
//   - storage.exposure.has_public_access_point (bool, always true when set)
//   - storage.exposure.public_access_point_names ([]any of string, sorted)
//
// An Access Point is "public-reaching" when storage.policy_is_public is
// true OR storage.public_access_fully_blocked is false. The join matches
// the bucket-side key storage.name against the AP-side key
// storage.bucket_name.
//
// Scope: single-snapshot, single-account. Neither side currently carries
// an account identifier, so a same-name bucket in a different account
// that an AP references cannot be distinguished from the local bucket.
// Cross-account AP→bucket joins need account identifiers on both sides
// first.
//
// Raw snapshots are never mutated: affected buckets get cloned Properties
// maps; every other asset is returned by value.
func EnrichBucketAPExposure(snapshots []asset.Snapshot) []asset.Snapshot {
	out := make([]asset.Snapshot, len(snapshots))
	for i, snap := range snapshots {
		out[i] = enrichSnapshotBucketAPExposure(snap)
	}
	return out
}

func enrichSnapshotBucketAPExposure(snap asset.Snapshot) asset.Snapshot {
	publicByBucket := collectPublicAccessPointsByBucket(snap)
	if len(publicByBucket) == 0 {
		return snap
	}

	enriched := snap
	enriched.Assets = make([]asset.Asset, len(snap.Assets))
	copy(enriched.Assets, snap.Assets)

	for i := range enriched.Assets {
		a := &enriched.Assets[i]
		if !a.IsType(bucketType()) {
			continue
		}
		storage, _ := a.Properties["storage"].(map[string]any)
		if storage == nil {
			continue
		}
		bucketName, _ := storage["name"].(string)
		apNames, ok := publicByBucket[bucketName]
		if !ok || bucketName == "" {
			continue
		}
		enriched.Assets[i] = withDerivedExposure(*a, apNames)
	}
	return enriched
}

// collectPublicAccessPointsByBucket walks the snapshot once and returns a
// map of bucket_name → sorted names of APs that are public-reaching.
func collectPublicAccessPointsByBucket(snap asset.Snapshot) map[string][]string {
	byBucket := map[string][]string{}
	for _, a := range snap.Assets {
		if !a.IsType(accessPointType()) {
			continue
		}
		storage, _ := a.Properties["storage"].(map[string]any)
		if storage == nil {
			continue
		}
		bucketName, _ := storage["bucket_name"].(string)
		if bucketName == "" {
			continue
		}
		if !isPublicReachingAP(storage) {
			continue
		}
		apName, _ := storage["name"].(string)
		if apName == "" {
			apName = string(a.ID)
		}
		byBucket[bucketName] = append(byBucket[bucketName], apName)
	}
	for k := range byBucket {
		slices.Sort(byBucket[k])
	}
	return byBucket
}

// isPublicReachingAP returns true when an Access Point would let traffic
// reach the bucket without going through bucket-level controls — either
// because the AP policy is public, or because the AP's own Public Access
// Block is not fully enforcing.
func isPublicReachingAP(storage map[string]any) bool {
	if policyPublic, ok := storage["policy_is_public"].(bool); ok && policyPublic {
		return true
	}
	// Default assumption when the PAB field is missing: treat as enforcing.
	// The AP contract documents public_access_fully_blocked as a required
	// derived boolean, so absence is "unknown / not public" rather than
	// "public". The derivation prefers false positives over false silence.
	if pabBlocked, ok := storage["public_access_fully_blocked"].(bool); ok && !pabBlocked {
		return true
	}
	return false
}

// withDerivedExposure returns a copy of the bucket asset with
// storage.exposure.has_public_access_point and
// storage.exposure.public_access_point_names set. apNames is expected
// sorted.
func withDerivedExposure(a asset.Asset, apNames []string) asset.Asset {
	newProps := cloneStringAnyMap(a.Properties)
	storage, _ := newProps["storage"].(map[string]any)
	if storage == nil {
		storage = map[string]any{}
		newProps["storage"] = storage
	}
	exposure, _ := storage["exposure"].(map[string]any)
	if exposure == nil {
		exposure = map[string]any{}
		storage["exposure"] = exposure
	}
	exposure["has_public_access_point"] = true
	exposure["public_access_point_names"] = toAnySlice(apNames)
	return asset.Asset{
		ID:         a.ID,
		Type:       a.Type,
		Vendor:     a.Vendor,
		Properties: newProps,
		Source:     a.Source,
	}
}

// cloneStringAnyMap deep-copies the subset of the property tree the
// derivation may touch. Maps-of-maps are cloned; scalars and untouched
// branches are shared by reference, which is safe because the derivation
// never writes into them.
func cloneStringAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if sub, ok := v.(map[string]any); ok {
			out[k] = cloneStringAnyMap(sub)
			continue
		}
		out[k] = v
	}
	return out
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
