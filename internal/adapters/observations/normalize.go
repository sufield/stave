package observations

import (
	"errors"

	"github.com/sufield/stave/internal/adapters/observations/schema"
	"github.com/sufield/stave/internal/core/asset"
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
//   - schema validation: surface "required field absent" warnings per asset
//     so a silent extractor regression becomes a visible log line, not an
//     invisible false-negative. The validation pass is non-fatal — a missing
//     required field is a warning, not an error, because the existing
//     property-bag pathway must keep working while the schema migration
//     proceeds. The CEL pathway is unchanged.
func normalizeSnapshotTypes(snapshot *asset.Snapshot) error {
	if snapshot == nil {
		return ErrNilSnapshot
	}
	if !snapshot.HasTimestamp() {
		return ErrMissingTimestamp
	}
	for i := range snapshot.Assets {
		snapshot.Assets[i].NormalizeProperties(normalizeProperties)
		if res, ok := schema.ValidateAsset(snapshot.Assets[i]); ok {
			// Only log when something is missing — quiet on the
			// happy path. Asset types without a registered schema
			// don't produce any log line at all.
			if len(res.MissingRequired) > 0 || len(res.MissingOptional) > 0 {
				schema.LogValidationResult(nil, res)
			}
		}
	}
	return nil
}
