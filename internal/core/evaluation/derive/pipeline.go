package derive

import "github.com/sufield/stave/internal/core/asset"

// Pipeline runs every registered derivation over the snapshot list and
// returns enriched snapshots. Call sites should pass the pipeline output
// directly to the evaluator; raw snapshots stay untouched for trace and
// audit purposes.
func Pipeline(snapshots []asset.Snapshot) []asset.Snapshot {
	return EnrichBucketAPExposure(snapshots)
}
