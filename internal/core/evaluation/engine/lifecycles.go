package engine

import (
	"fmt"
	"log/slog"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// BuildLifecyclesPerControl constructs chronological lifecycles for each asset
// across all controls. The outer loop iterates snapshots (time), the middle
// loop iterates assets, and the inner loop evaluates each control's predicate
// to record whether the asset was unsafe at that point in time.
//
// Controls are pre-indexed by vendor scope tag so only relevant controls
// are evaluated per asset, reducing the inner loop from O(C) to O(c)
// where c is the number of controls matching the asset's vendor.
func BuildLifecyclesPerControl(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	celEval policy.PredicateEval,
) (map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, error) {

	lifecyclesByControl := make(map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, len(controls))
	for i := range controls {
		ctl := &controls[i]
		lifecyclesByControl[ctl.ID] = make(map[asset.ID]*asset.ExposureLifecycle)
	}

	// Pre-index controls by vendor scope tag.
	ctlIndex := buildControlVendorIndex(controls)

	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			relevant := ctlIndex.controlsFor(a.Vendor, controls)
			if err := recordAssetObservation(a, snap, relevant, celEval, lifecyclesByControl); err != nil {
				return nil, err
			}
		}
	}

	return lifecyclesByControl, nil
}

// controlVendorIndex maps vendor strings to the indices of controls
// whose scope tags include that vendor. Controls with no scope tags
// are treated as universal (applicable to all vendors).
type controlVendorIndex struct {
	byVendor  map[string][]int                      // vendor string → control indices
	universal []int                                 // controls with no scope tags
	cache     map[string][]policy.ControlDefinition // vendor → cached result
}

func buildControlVendorIndex(controls []policy.ControlDefinition) controlVendorIndex {
	idx := controlVendorIndex{
		byVendor: make(map[string][]int),
		cache:    make(map[string][]policy.ControlDefinition),
	}
	for i := range controls {
		ctl := &controls[i]
		if len(ctl.ScopeTags) == 0 {
			idx.universal = append(idx.universal, i)
			continue
		}
		added := false
		for _, tag := range ctl.ScopeTags {
			s := string(tag)
			// Vendor tags are short identifiers like "aws", "gcp", "azure".
			if len(s) <= 10 {
				idx.byVendor[s] = append(idx.byVendor[s], i)
				added = true
			}
		}
		if !added {
			idx.universal = append(idx.universal, i)
		}
	}
	return idx
}

func (idx controlVendorIndex) controlsFor(vendor kernel.Vendor, all []policy.ControlDefinition) []policy.ControlDefinition {
	vendorStr := string(vendor)

	// Return cached result if available — avoids per-asset allocation.
	if cached, ok := idx.cache[vendorStr]; ok {
		return cached
	}

	indices := idx.byVendor[vendorStr]
	if len(indices) == 0 && len(idx.universal) == 0 {
		return all // no index data — fall back to full scan
	}

	seen := make(map[int]bool, len(indices)+len(idx.universal))
	result := make([]policy.ControlDefinition, 0, len(indices)+len(idx.universal))
	for _, i := range indices {
		if !seen[i] {
			seen[i] = true
			result = append(result, all[i])
		}
	}
	for _, i := range idx.universal {
		if !seen[i] {
			seen[i] = true
			result = append(result, all[i])
		}
	}

	// Cache for future calls with the same vendor.
	if idx.cache != nil {
		idx.cache[vendorStr] = result
	}
	return result
}

// recordAssetObservation evaluates a single asset against all controls at one
// point in time, updating the corresponding lifecycles. Extracted from the
// triple-nested loop to reduce indentation and clarify the per-asset logic.
func recordAssetObservation(
	a asset.Asset,
	snap asset.Snapshot,
	controls []policy.ControlDefinition,
	celEval policy.PredicateEval,
	lifecyclesByControl map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle,
) error {
	for i := range controls {
		ctl := &controls[i]
		lcs := lifecyclesByControl[ctl.ID]

		t, exists := lcs[a.ID]
		if !exists {
			t = asset.NewExposureLifecycle(a)
			lcs[a.ID] = t
		}

		isUnsafe, evalErr := checkUnsafe(*ctl, a, snap, celEval)
		if evalErr != nil {
			slog.Warn("skipping inconclusive check", "control", ctl.ID, "asset", a.ID, "error", evalErr)
			continue // Do not record — check is inconclusive
		}
		if err := t.RecordCheck(snap.CapturedAt, isUnsafe); err != nil {
			return fmt.Errorf("record observation for control %s, asset %s: %w", ctl.ID, a.ID, err)
		}
		t.SetAsset(a)
	}
	return nil
}

// checkUnsafe evaluates an asset against a control predicate using the CEL evaluator.
// Returns (result, err). On error, the caller must NOT record the asset as safe —
// the check is inconclusive and should be skipped.
func checkUnsafe(
	ctl policy.ControlDefinition,
	a asset.Asset,
	snap asset.Snapshot,
	celEval policy.PredicateEval,
) (bool, error) {
	if celEval == nil {
		return false, fmt.Errorf("CEL evaluator is nil for control %s on asset %s", ctl.ID, a.ID)
	}
	result, err := celEval(ctl, a, snap.Identities)
	if err != nil {
		return false, fmt.Errorf("CEL evaluation failed for control %s on asset %s: %w", ctl.ID, a.ID, err)
	}
	return result, nil
}
