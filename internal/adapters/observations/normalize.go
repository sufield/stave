package observations

import (
	"errors"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
)

// Sentinel errors for observation normalization.
var (
	// ErrNilSnapshot is returned when a nil snapshot is passed for normalization.
	ErrNilSnapshot = errors.New("snapshot is nil")

	// ErrMissingTimestamp is returned when a snapshot lacks a valid captured_at timestamp.
	ErrMissingTimestamp = errors.New("captured_at must be a non-zero RFC3339 timestamp")
)

// normalizeSnapshotTypes performs post-unmarshal normalization on a snapshot.
//
// AssetType and Vendor are already normalized during json.Unmarshal via their
// UnmarshalJSON methods. This function handles the remaining concerns:
//   - nil snapshot and missing timestamp validation
//   - property value coercion (string-encoded bools/numbers from sloppy extractors)
func normalizeSnapshotTypes(snapshot *asset.Snapshot) error {
	if snapshot == nil {
		return ErrNilSnapshot
	}
	if !snapshot.HasTimestamp() {
		return ErrMissingTimestamp
	}
	for i := range snapshot.Assets {
		if snapshot.Assets[i].Properties != nil {
			normalizeProperties(snapshot.Assets[i].Properties)
		}
	}
	return nil
}
