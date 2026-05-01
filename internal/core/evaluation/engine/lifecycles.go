package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
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
//
// Concurrency contract: NOT safe for concurrent use. The current
// caller (BuildLifecyclesPerControl) iterates snapshots
// sequentially. If a future caller wants to parallelize, add a
// sync.Mutex around the cache map; do NOT remove it and rely on
// "value receiver makes copies" — the cache map is a reference
// type, so copies still share state.
type controlVendorIndex struct {
	scopeTags [][]kernel.ScopeTag                          // per-control scope tags
	cache     map[kernel.Vendor][]policy.ControlDefinition // vendor → cached result
}

func buildControlVendorIndex(controls []policy.ControlDefinition) *controlVendorIndex {
	tagsPerCtl := make([][]kernel.ScopeTag, len(controls))
	for i := range controls {
		tagsPerCtl[i] = controls[i].ScopeTags
	}
	return &controlVendorIndex{
		scopeTags: tagsPerCtl,
		cache:     make(map[kernel.Vendor][]policy.ControlDefinition),
	}
}

// Pointer receiver: the cache map mutation should be visible across
// the index's lifetime, and a value receiver was misleading because
// the underlying map field made the cache writes "work" even
// though they read as a per-call mutation. Pointer makes the
// shared-state contract explicit.
func (idx *controlVendorIndex) controlsFor(vendor kernel.Vendor, all []policy.ControlDefinition) []policy.ControlDefinition {
	// Return a CLONE of the cached result. The cache holds the
	// canonical filtered list per vendor; if a caller mutated the
	// returned slice (sort, append, swap-replace), the next caller
	// would see the corrupted ordering or a length mismatch with
	// the underlying scopeTags. Cloning at the read boundary keeps
	// the cache immutable from the caller's perspective without
	// requiring callers to remember to clone themselves.
	if cached, ok := idx.cache[vendor]; ok {
		return slices.Clone(cached)
	}

	var result []policy.ControlDefinition
	for i := range all {
		if kernel.AppliesToVendor(idx.scopeTags[i], vendor) {
			result = append(result, all[i])
		}
	}

	if idx.cache != nil {
		idx.cache[vendor] = result
	}
	// Return a clone here too so the first caller cannot mutate
	// the just-cached slice via the returned reference.
	return slices.Clone(result)
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
			newLC, lcErr := asset.NewExposureLifecycle(a)
			if lcErr != nil {
				// Empty asset ID means upstream produced a
				// malformed observation row. Skip this asset
				// only — the rest of the assessment must keep
				// running so a single bad row doesn't blank the
				// whole report.
				if errors.Is(lcErr, asset.ErrEmptyAssetID) {
					slog.Warn("skipping asset with empty ID",
						"control", ctl.ID, "asset_type", a.Type)
					continue
				}
				return lcErr
			}
			t = newLC
			lcs[a.ID] = t
		}

		isUnsafe, evalErr := checkUnsafe(*ctl, a, snap, celEval)
		if evalErr != nil {
			// Per AGENTS.md, core/ avoids stderr-level side effects:
			// the inconclusive condition is the return-value channel
			// (RecordInconclusive below) and operators see it in the
			// assessment output. Diagnostic detail is logged at Info
			// so operators with -v can correlate the underlying CEL
			// error with the inconclusive verdict without the message
			// implying an actionable Error/Warn.
			errStr := evalErr.Error()
			category := "inconclusive"
			if strings.Contains(errStr, "compile") || strings.Contains(errStr, "parse") || strings.Contains(errStr, "undeclared") {
				category = "compilation_failed"
			}
			slog.Info("control evaluation inconclusive",
				"control", ctl.ID, "asset", a.ID, "category", category, "error", evalErr)
			if recErr := t.RecordInconclusive(snap.CapturedAt); recErr != nil {
				return fmt.Errorf("record inconclusive for control %s, asset %s: %w", ctl.ID, a.ID, recErr)
			}
			continue
		}
		if err := t.RecordCheck(snap.CapturedAt, isUnsafe); err != nil {
			return fmt.Errorf("record observation for control %s, asset %s: %w", ctl.ID, a.ID, err)
		}
		if err := t.SetAsset(a); err != nil {
			return fmt.Errorf("set asset for control %s, asset %s: %w", ctl.ID, a.ID, err)
		}
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
