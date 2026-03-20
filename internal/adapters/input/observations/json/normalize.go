package json

import (
	"errors"
	"fmt"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
)

// Sentinel errors for observation normalization.
var (
	// ErrNilSnapshot is returned when a nil snapshot is passed for normalization.
	ErrNilSnapshot = errors.New("snapshot is nil")

	// ErrMissingTimestamp is returned when a snapshot lacks a valid captured_at timestamp.
	ErrMissingTimestamp = errors.New("captured_at must be a non-zero RFC3339 timestamp")
)

// normalizeSnapshotTypes enforces domain-level type parsing after schema validation.
func normalizeSnapshotTypes(snapshot *asset.Snapshot) error {
	if snapshot == nil {
		return ErrNilSnapshot
	}
	if !snapshot.HasTimestamp() {
		return ErrMissingTimestamp
	}
	for i := range snapshot.Assets {
		if err := normalizeTypeAndVendor(&snapshot.Assets[i].Type, &snapshot.Assets[i].Vendor, "assets", i); err != nil {
			return fmt.Errorf("normalize snapshot assets: %w", err)
		}
		if snapshot.Assets[i].Properties != nil {
			normalizeProperties(snapshot.Assets[i].Properties)
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
	vendor, err := kernel.NewVendor(v.String())
	if err != nil {
		return fmt.Errorf("%s[%d].vendor: %w", label, index, err)
	}
	*t = rt
	*v = vendor
	return nil
}
