package observations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// BundleLoader implements appcontracts.SnapshotBundleLoader for the
// single-file multi-snapshot observation bundle format. Distinct from
// ObservationLoader (directory of files) because bundles skip per-file
// schema validation — see ParseBundle for why.
type BundleLoader struct{}

// NewBundleLoader returns the standard bundle loader.
func NewBundleLoader() *BundleLoader { return &BundleLoader{} }

var _ appcontracts.SnapshotBundleLoader = (*BundleLoader)(nil)

// LoadBundle reads and parses a bundle file. The ctx parameter is accepted
// for interface conformance; the underlying read is not yet cancellation-aware.
func (BundleLoader) LoadBundle(_ context.Context, path string) ([]asset.Snapshot, error) {
	return LoadBundle(path)
}

// ObservationBundle represents a bundled observations file containing multiple snapshots.
type ObservationBundle struct {
	SchemaVersion kernel.Schema    `json:"schema_version"`
	Snapshots     []asset.Snapshot `json:"snapshots"`
}

// ParseBundle unmarshals observation bundle JSON from raw bytes
// and applies minimum-shape validation: the top-level
// `snapshots` array must be present and non-empty, and every
// contained snapshot must carry a non-zero `captured_at`
// timestamp.
//
// Why bundle entries are NOT schema-validated against the
// obs.v0.1 single-file schema: the obs.v0.1 schema requires
// `schema_version`, `captured_at`, and `assets` at the top
// level. Bundle entries omit `schema_version` (it's hoisted to
// the bundle wrapper), so applying the single-file schema would
// reject every legitimate bundle. The validation contract is
// instead carried by the type-system (ObservationBundle field
// definitions) and the explicit captured_at + non-empty
// snapshots checks below. Single-file intake (loader_core.go)
// runs the full schema validator because each file is itself a
// complete obs.v0.1 document.
//
// Standard directory loading runs equivalent shape checks via
// ObservationLoader.process; bundle loading must match.
func ParseBundle(data []byte) ([]asset.Snapshot, error) {
	var bundle ObservationBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse observations JSON: %w", err)
	}
	if len(bundle.Snapshots) == 0 {
		return nil, errors.New("observation bundle contains no snapshots (expected a top-level `snapshots` array)")
	}
	for i := range bundle.Snapshots {
		if bundle.Snapshots[i].CapturedAt.IsZero() {
			return nil, fmt.Errorf("observation bundle snapshot %d is missing required `captured_at` timestamp", i)
		}
		// Mirror loader_core.go: bundle and directory loaders must
		// produce snapshots with the same shape, otherwise predicates
		// that depend on type-coerced fields (asset.ID, kernel.AssetType)
		// silently behave differently between the two intake paths.
		if err := normalizeSnapshotTypes(&bundle.Snapshots[i]); err != nil {
			return nil, fmt.Errorf("normalize snapshot %d: %w", i, err)
		}
	}
	return bundle.Snapshots, nil
}

// LoadBundle reads and unmarshals an observation bundle from the given path.
func LoadBundle(path string) ([]asset.Snapshot, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read observations file: %w", err)
	}
	return ParseBundle(data)
}
