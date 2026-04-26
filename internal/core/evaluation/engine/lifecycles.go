package engine

import (
	"fmt"
	"log/slog"
	"strings"

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

// controlVendorIndex memoizes the per-vendor list of applicable
// controls. Membership is computed via kernel.AppliesToVendor —
// the single source of truth for the vendor-applicability
// heuristic shared with the risk pipeline.
type controlVendorIndex struct {
	stringTags [][]string                            // per-control pre-stringified scope tags
	cache      map[string][]policy.ControlDefinition // vendor → cached result
}

func buildControlVendorIndex(controls []policy.ControlDefinition) controlVendorIndex {
	stringTags := make([][]string, len(controls))
	for i := range controls {
		tags := controls[i].ScopeTags
		if len(tags) == 0 {
			continue
		}
		s := make([]string, len(tags))
		for j, t := range tags {
			s[j] = string(t)
		}
		stringTags[i] = s
	}
	return controlVendorIndex{
		stringTags: stringTags,
		cache:      make(map[string][]policy.ControlDefinition),
	}
}

func (idx controlVendorIndex) controlsFor(vendor kernel.Vendor, all []policy.ControlDefinition) []policy.ControlDefinition {
	vendorStr := string(vendor)

	// Return cached result if available — avoids per-asset
	// re-evaluation of the heuristic.
	if cached, ok := idx.cache[vendorStr]; ok {
		return cached
	}

	var result []policy.ControlDefinition
	for i := range all {
		if kernel.AppliesToVendor(idx.stringTags[i], vendorStr) {
			result = append(result, all[i])
		}
	}

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
		// Asset-type gate. Skip silently when the control declares its
		// applicable types and the current asset is not in the list. No
		// finding, no lifecycle entry, no inconclusive — the control is
		// absent from output for this asset, identical to the asset
		// being outside the control's declared scope.
		if !ctl.AppliesToAssetType(a.Type) {
			continue
		}
		lcs := lifecyclesByControl[ctl.ID]

		t, exists := lcs[a.ID]
		if !exists {
			t = asset.NewExposureLifecycle(a)
			lcs[a.ID] = t
		}

		isUnsafe, evalErr := checkUnsafe(*ctl, a, snap, celEval)
		if evalErr != nil {
			errStr := evalErr.Error()
			if strings.Contains(errStr, "compile") || strings.Contains(errStr, "parse") || strings.Contains(errStr, "undeclared") {
				slog.Error("control predicate compilation failed",
					"control", ctl.ID, "asset", a.ID, "error", evalErr)
			} else {
				slog.Warn("inconclusive check",
					"control", ctl.ID, "asset", a.ID, "error", evalErr)
			}
			if recErr := t.RecordInconclusive(snap.CapturedAt); recErr != nil {
				return fmt.Errorf("record inconclusive for control %s, asset %s: %w", ctl.ID, a.ID, recErr)
			}
			continue
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
