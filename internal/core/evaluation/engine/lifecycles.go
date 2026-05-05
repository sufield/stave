package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ErrNilCELEvaluator is returned when checkUnsafe is called without a
// configured CEL evaluator. Exposed as a sentinel so callers can use
// errors.Is to distinguish "evaluator missing" from genuine evaluation
// failures inside the CEL runtime.
var ErrNilCELEvaluator = errors.New("engine: CEL evaluator is nil")

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
// SAFE for concurrent use via the internal sync.RWMutex.
// controlsFor uses double-checked locking:
//
//  1. RLock + read cache. Hit → return slices.Clone, RUnlock.
//  2. RUnlock + compute the filtered list outside the lock so a
//     long compute doesn't block other readers.
//  3. Lock + re-check the cache (a peer may have raced us to the
//     same key while we computed). If still missing, store our
//     result; otherwise discard our compute and return the peer's
//     clone.
//
// The cache holds the canonical filtered list per vendor. Every
// callsite returns a slices.Clone so a caller mutating the returned
// slice (sort, append, swap-replace) cannot corrupt the cached
// entry the next caller reads.
//
// Do NOT rely on "value receiver makes copies" — the cache map is a
// reference type, so copies still share state. Tests that
// inadvertently introduce a race here surface as nondeterministic
// `go test -race` failures, not silent data corruption — exercise
// the assessor under -race when adding parallelism.
type controlVendorIndex struct {
	scopeTags [][]kernel.ScopeTag // per-control scope tags
	// mu guards cache. Concurrent callers (a parallel
	// per-vendor evaluation pipeline, a watch loop reading the
	// posture cache while a fresh assessment writes to it) take
	// RLock for reads and Lock for writes. The previous unguarded
	// map produced fatal "concurrent map writes" runtime panics
	// under -race when introducing per-vendor parallelism.
	mu    sync.RWMutex
	cache map[kernel.Vendor][]policy.ControlDefinition // vendor → cached result
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
	idx.mu.RLock()
	cached, ok := idx.cache[vendor]
	idx.mu.RUnlock()
	if ok {
		return slices.Clone(cached)
	}

	var result []policy.ControlDefinition
	for i := range all {
		if kernel.AppliesToVendor(idx.scopeTags[i], vendor) {
			result = append(result, all[i])
		}
	}

	// Re-check under the write lock: a concurrent caller may have
	// produced the same result and cached it between RUnlock and
	// Lock. Prefer the existing cached value to avoid duplicating
	// the slice.
	idx.mu.Lock()
	if cached, ok := idx.cache[vendor]; ok {
		idx.mu.Unlock()
		return slices.Clone(cached)
	}
	// idx.cache is initialized by buildControlVendorIndex (the only
	// constructor) and never reset to nil, so an explicit nil-check
	// here is dead code.
	idx.cache[vendor] = result
	idx.mu.Unlock()
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
		if lcs == nil {
			// BuildLifecyclesPerControl pre-registers a map for every
			// control ID up front, so this branch only fires when the
			// caller passed a control whose ID wasn't in the
			// pre-registration set — typically a hand-built test
			// fixture or a future caller that forgets the
			// initialisation step. Skip + warn instead of panicking
			// on the lcs[a.ID] = t write below.
			slog.Warn("recordAssetObservation: control ID not pre-registered in lifecycles map; skipping",
				"control", ctl.ID, "asset", a.ID)
			continue
		}

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

		isUnsafe, evalErr := checkUnsafe(ctl, a, snap, celEval)
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
			// A lifecycle with an empty ID is upstream-input malformed —
			// the previous shape panicked here and aborted the whole
			// assessment. Skip just this lifecycle and keep going so
			// one bad observation row no longer blanks the entire run.
			if errors.Is(err, asset.ErrEmptyAssetID) {
				slog.Warn("skipping lifecycle with empty asset ID",
					"control", ctl.ID, "asset_type", a.Type)
				continue
			}
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
//
// Pointer ctl: ControlDefinition crossed gocritic's hugeParam
// threshold (584 bytes after Iter 5.1's ForbiddenState addition).
// The eval boundary still receives the struct by value — the
// PredicateEval signature is fixed by every callsite in the
// engine — but routing into checkUnsafe by pointer avoids a
// per-asset copy in the hot lifecycle loop.
func checkUnsafe(
	ctl *policy.ControlDefinition,
	a asset.Asset,
	snap asset.Snapshot,
	celEval policy.PredicateEval,
) (bool, error) {
	if celEval == nil {
		return false, fmt.Errorf("%w: control %s on asset %s", ErrNilCELEvaluator, ctl.ID, a.ID)
	}
	result, err := celEval(*ctl, a, snap.Identities)
	if err != nil {
		return false, fmt.Errorf("CEL evaluation failed for control %s on asset %s: %w", ctl.ID, a.ID, err)
	}
	return result, nil
}
