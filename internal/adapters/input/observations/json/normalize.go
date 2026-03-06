package json

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/asset"
)

// normalizeSnapshotTypes enforces domain-level type parsing after schema validation.
func normalizeSnapshotTypes(snapshot *asset.Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is nil")
	}
	if !snapshot.HasTimestamp() {
		return fmt.Errorf("captured_at must be a non-zero RFC3339 timestamp")
	}
	for i := range snapshot.Resources {
		if err := normalizeTypeAndVendor(&snapshot.Resources[i].Type, &snapshot.Resources[i].Vendor, "resources", i); err != nil {
			return fmt.Errorf("normalize snapshot resources: %w", err)
		}
	}
	for i := range snapshot.Identities {
		if err := normalizeTypeAndVendor(&snapshot.Identities[i].Type, &snapshot.Identities[i].Vendor, "identities", i); err != nil {
			return fmt.Errorf("normalize snapshot identities: %w", err)
		}
	}
	return nil
}

func normalizeTypeAndVendor(t *kernel.AssetType, v *kernel.Vendor, label string, index int) error {
	rt := kernel.NewAssetType(t.String())
	if err := rt.Validate(); err != nil {
		return fmt.Errorf("%s[%d].type: %w", label, index, err)
	}
	vendor, err := kernel.ParseVendor(v.String())
	if err != nil {
		return fmt.Errorf("%s[%d].vendor: %w", label, index, err)
	}
	*t = rt
	*v = vendor
	return nil
}
