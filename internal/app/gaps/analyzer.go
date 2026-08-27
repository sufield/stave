package gaps

import (
	"strings"
	"time"

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
	controlAppliesTo := map[kernel.ControlID]map[kernel.AssetType]struct{}{}
	for i := range controls {
		ctl := &controls[i]
		m := map[kernel.AssetType]struct{}{}
		for _, at := range ctl.ApplicableAssetTypes {
			m[at] = struct{}{}
		}
		controlAppliesTo[ctl.ID] = m
	}
	controlReadsPath := map[kernel.ControlID]map[string]struct{}{}
	for path, ctls := range idx.PathToControls {
		for _, id := range ctls {
			if controlReadsPath[id] == nil {
				controlReadsPath[id] = map[string]struct{}{}
			}
			controlReadsPath[id][path] = struct{}{}
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
			if at, ok := controlAppliesTo[id]; ok {
				_, ok2 := at[k.t]
				if len(at) == 0 || ok2 {
					controlsBlocked = append(controlsBlocked, id)
				}
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
					var reads bool
					if rp, ok := controlReadsPath[member]; ok {
						_, reads = rp[k.p]
					}
					var applies bool
					if at, ok := controlAppliesTo[member]; ok {
						_, applies = at[k.t]
					}
					if reads && applies {
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
		_, isIntent := intentSet[k.p]
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

func latestPerAsset(snapshots []asset.Snapshot) map[asset.ID]asset.Asset {
	out := map[asset.ID]asset.Asset{}
	latestTime := map[asset.ID]time.Time{}
	for i := range snapshots {
		for j := range snapshots[i].Assets {
			a := &snapshots[i].Assets[j]
			prevTime, ok := latestTime[a.ID]
			if !ok || !snapshots[i].CapturedAt.Before(prevTime) {
				out[a.ID] = *a
				latestTime[a.ID] = snapshots[i].CapturedAt
			}
		}
	}
	return out
}

// intentPaths returns the canonical set of "intent property"
// paths. Hardcoded for v1; a follow-on commit will read these
// from internal/controldata/taxonomy/intent_properties.yaml so
// the set grows without code edits.
func intentPaths() map[string]struct{} {
	return map[string]struct{}{
		"properties.storage.tags.data_classification": {},
		"properties.storage.tags.environment":         {},
		"properties.identity.tags.role-type":          {},
		"properties.identity.tags.environment":        {},
		"properties.compute.tags.environment":         {},
		"properties.ai.tags.environment":              {},
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
		case RemediationTag:
			s.TagGaps++
		case RemediationAPI:
			s.ApiGaps++
		case RemediationDerived:
			s.DerivedGaps++
		case RemediationCollector:
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

	if topN > 0 && len(gaps) > 0 {
		n := min(topN, len(gaps))
		top := map[kernel.ChainID]struct{}{}
		tagN := 0
		for i := range n {
			for _, c := range gaps[i].ChainsBlocked {
				top[c] = struct{}{}
			}
			if gaps[i].Remediation.Type == RemediationTag {
				tagN++
			}
		}
		s.ChainsUnblockedByTopN = len(top)
		s.TopN = n
		// Crude effort sum: 30 sec * (tag gaps in top N) +
		// generic "per-asset" multiplier. For collector gaps
		// estimates are too organisation-specific to predict.
		if tagN > 0 {
			s.QuickWinTimeEstimate = "tens of minutes (tag-based fixes only)"
		}
	}
	return s
}
