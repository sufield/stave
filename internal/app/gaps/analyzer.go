package gaps

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predindex"
)

// Analyze produces the gap report. The caller has already loaded
// controls, chains, and the observation snapshot slice. Analyze
// is pure (no I/O, no engine calls); the same inputs produce the
// same report.
//
// topN bounds the "chains unblocked by top N" calculation in the
// summary; a non-positive value disables it. Per-gap priority
// ordering is independent of topN.
func Analyze(controls []policy.ControlDefinition, chains []policy.ChainDefinition, snapshots []asset.Snapshot, topN int) Report {
	idx := predindex.Build(controls, chains)

	// Observed assets indexed by asset.ID → latest snapshot's
	// properties. Multiple snapshots over time may carry the
	// same asset; we take the latest. Walking from the last
	// snapshot back lets us short-circuit on first-seen.
	latest := latestPerAsset(snapshots)

	// Per-(type, path), count how many observed assets of the
	// type lack the path. "Lack" semantics: any segment along
	// the path doesn't resolve to a present non-null value
	// (brief rule #6: absent != false; present-with-any-value
	// is not a gap).
	type key struct {
		t kernel.AssetType
		p string
	}
	missing := map[key]int{}
	totals := map[kernel.AssetType]int{}

	for _, a := range latest {
		totals[a.Type]++
		paths, ok := idx.TypeToPaths[a.Type]
		if !ok {
			continue
		}
		for _, p := range paths {
			if !hasProperty(a, p) {
				missing[key{a.Type, p}]++
			}
		}
	}

	// Build a per-control "applicable to type T?" lookup so the
	// per-gap controls_blocked count filters to controls that
	// actually fire on the gap's asset type. Without this filter
	// a Lambda gap on properties.network.kind would inflate to
	// the catalog-wide count of every control reading that path,
	// including VPC/security-group controls that never see a
	// Lambda asset.
	controlAppliesTo := map[kernel.ControlID]map[kernel.AssetType]bool{}
	for i := range controls {
		ctl := &controls[i]
		m := map[kernel.AssetType]bool{}
		for _, at := range ctl.ApplicableAssetTypes {
			m[at] = true
		}
		controlAppliesTo[ctl.ID] = m
	}
	controlReadsPath := map[kernel.ControlID]map[string]bool{}
	for path, ctls := range idx.PathToControls {
		for _, id := range ctls {
			if controlReadsPath[id] == nil {
				controlReadsPath[id] = map[string]bool{}
			}
			controlReadsPath[id][path] = true
		}
	}

	intentSet := intentPaths()
	gaps := make([]FieldGap, 0, len(missing))
	for k, count := range missing {
		// Restrict controls_blocked to controls applicable to
		// the gap's asset type. PathToControls is keyed only on
		// path, so we have to filter here per (path, type).
		var controlsBlocked []kernel.ControlID
		for _, id := range idx.PathToControls[k.p] {
			if controlAppliesTo[id][k.t] {
				controlsBlocked = append(controlsBlocked, id)
			}
		}
		// Same intersection for chains: a chain is blocked by
		// this gap only when some chain member both reads the
		// path AND applies to the gap's asset type.
		var chainsBlocked []kernel.ChainID
		for _, chainID := range idx.PathToChains[k.p] {
			// Find the chain definition and check membership.
			for ci := range chains {
				if chains[ci].ID != chainID {
					continue
				}
				blocks := false
				for _, member := range chains[ci].ControlIDs {
					if controlReadsPath[member][k.p] && controlAppliesTo[member][k.t] {
						blocks = true
						break
					}
				}
				if blocks {
					chainsBlocked = append(chainsBlocked, chainID)
				}
				break
			}
		}
		isIntent := intentSet[k.p]
		gaps = append(gaps, FieldGap{
			PropertyPath:         k.p,
			AssetType:            k.t,
			MissingCount:         count,
			TotalCount:           totals[k.t],
			ControlsBlocked:      controlsBlocked,
			ControlsBlockedCount: len(controlsBlocked),
			ChainsBlocked:        chainsBlocked,
			ChainsBlockedCount:   len(chainsBlocked),
			MaxSeverity:          idx.PathMaxSeverity[k.p],
			IsIntentProperty:     isIntent,
			Remediation:          classifyRemediation(k.p, k.t, isIntent),
		})
	}

	Prioritize(gaps)
	for i := range gaps {
		gaps[i].Priority = i + 1
	}

	return Report{
		Gaps:    gaps,
		Summary: buildSummary(gaps, indeterminateCount(controls), topN),
	}
}

// hasProperty returns true when the path resolves to a non-null
// value on the asset. The path is the predicate's verbatim path
// (e.g. "properties.storage.tags.data_classification"); we strip
// the "properties." prefix since asset.Properties IS the
// properties block.
func hasProperty(a asset.Asset, path string) bool {
	rel := strings.TrimPrefix(path, "properties.")
	if rel == path {
		// Path didn't start with "properties." — predicates
		// occasionally reference envelope-level fields (vendor,
		// type). Those are always set; treat as present.
		return true
	}
	cur := any(a.Properties)
	for seg := range strings.SplitSeq(rel, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		v, exists := m[seg]
		if !exists || v == nil {
			return false
		}
		cur = v
	}
	return true
}

// latestPerAsset deduplicates assets by ID, retaining the latest
// snapshot's view. When two snapshots carry the same asset, the
// snapshot with the later CapturedAt wins; ties resolve in
// snapshot order. Callers reading freshness from this map should
// be aware that asset.LastSeen would be a more accurate query;
// for gap purposes "do you observe this property NOW?" is the
// right semantic.
func latestPerAsset(snapshots []asset.Snapshot) map[asset.ID]asset.Asset {
	out := map[asset.ID]asset.Asset{}
	for i := range snapshots {
		for j := range snapshots[i].Assets {
			a := &snapshots[i].Assets[j]
			cur, ok := out[a.ID]
			if !ok || !snapshots[i].CapturedAt.Before(snapshotOf(cur, snapshots).CapturedAt) {
				out[a.ID] = *a
			}
		}
	}
	return out
}

// snapshotOf is a no-op helper retained for symmetry with the
// "find the snapshot that produced this asset" path; for now we
// don't need it (latestPerAsset uses snapshot ordering only). A
// follow-on could carry the CapturedAt on the Asset itself.
func snapshotOf(_ asset.Asset, snaps []asset.Snapshot) asset.Snapshot {
	if len(snaps) == 0 {
		return asset.Snapshot{}
	}
	return snaps[len(snaps)-1]
}

// intentPaths returns the canonical set of "intent property"
// paths. Hardcoded for v1; a follow-on commit will read these
// from internal/controldata/taxonomy/intent_properties.yaml so
// the set grows without code edits.
func intentPaths() map[string]bool {
	return map[string]bool{
		"properties.storage.tags.data_classification": true,
		"properties.storage.tags.environment":         true,
		"properties.identity.tags.role-type":          true,
		"properties.identity.tags.environment":        true,
		"properties.compute.tags.environment":         true,
		"properties.ai.tags.environment":              true,
	}
}

// indeterminateCount returns the number of controls without an
// applicable_asset_types declaration. The summary surfaces this
// so the operator knows the gap report covers only the
// declarable subset.
func indeterminateCount(controls []policy.ControlDefinition) int {
	n := 0
	for i := range controls {
		if len(controls[i].ApplicableAssetTypes) == 0 {
			n++
		}
	}
	return n
}

func buildSummary(gaps []FieldGap, indet int, topN int) Summary {
	s := Summary{
		TotalGaps:             len(gaps),
		IndeterminateControls: indet,
	}
	if indet > 0 {
		s.IndeterminateDisclaimer = "Additional gaps may exist on controls without applicable_asset_types declarations; run `stave readiness` for asset-type-level coverage."
	}
	chainSet := map[kernel.ChainID]struct{}{}
	for i := range gaps {
		r := gaps[i].Remediation
		switch r.Type {
		case "tag":
			s.TagGaps++
		case "api":
			s.ApiGaps++
		case "derived":
			s.DerivedGaps++
		case "collector":
			s.CollectorGaps++
		default:
			// classifyRemediation only emits one of the four known
			// types. Any other value is a bug — bucket it as
			// "collector" so the counts still partition TotalGaps
			// while the unknown type leaks into the gap list for
			// debugging.
			s.CollectorGaps++
		}
		if r.FixableByAgent {
			s.FixableByAgentGaps++
		} else {
			s.NotFixableByAgentGaps++
		}
		for _, c := range gaps[i].ChainsBlocked {
			chainSet[c] = struct{}{}
		}
	}
	s.ChainsBlockedTotal = len(chainSet)

	if topN > 0 && topN <= len(gaps) {
		top := map[kernel.ChainID]struct{}{}
		tagN := 0
		for i := range topN {
			for _, c := range gaps[i].ChainsBlocked {
				top[c] = struct{}{}
			}
			if gaps[i].Remediation.Type == "tag" {
				tagN++
			}
		}
		s.ChainsUnblockedByTopN = len(top)
		s.TopN = topN
		// Crude effort sum: 30 sec * (tag gaps in top N) +
		// generic "per-asset" multiplier. For collector gaps
		// estimates are too organisation-specific to predict.
		if tagN > 0 {
			s.QuickWinTimeEstimate = "tens of minutes (tag-based fixes only)"
		}
	}
	return s
}
