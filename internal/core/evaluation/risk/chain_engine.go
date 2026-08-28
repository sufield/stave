package risk

import (
	"cmp"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// FailingControl is a (control, asset) pair for a detected violation.
// Used as input to chain and attack-stage analysis to preserve asset context.
// Stays in risk/ as a chain-engine input type — it isn't carried on
// report.Assessment, so it doesn't migrate to findings/.
type FailingControl struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// ScopeResolver returns the value at the given property path on the
// asset identified by assetID. The second return is false when the
// asset is unknown or the path resolves to an empty / non-scalar
// value. The chain engine treats false the same as ScopeField unset
// for that one (asset, chain) pair: the failing control falls back to
// asset.ID grouping.
type ScopeResolver func(assetID asset.ID, path string) (string, bool)

// chainBuckets is the per-chain accumulator built during the
// failure walk. Held as a slice indexed by chain index so chains
// that never fire pay only the nil-check at emission time, not the
// per-chain map allocation.
type chainBuckets struct {
	byScope         map[string]map[kernel.ControlID]struct{}
	assetsByScope   map[string]map[asset.ID]struct{}
	resolvedByScope map[string]struct{}
}

// DetectChains checks each chain definition: a chain fires only when
// enough of its member controls fail within a single grouping bucket.
// The grouping bucket is asset.ID by default; when the chain declares
// ScopeField, it is the resolved value of that property path on each
// failing asset (e.g. user_pool_id reuniting per-trigger Cognito
// ghost findings that surface on distinct asset.IDs).
//
// failures is the set of (control, asset) pairs with active violations.
// chains is the catalog of chain definitions to check.
// controlLookup maps control IDs to their definitions (attack stage,
// blast multiplier).
// scopeResolver may be nil; when nil, every chain falls back to
// asset.ID grouping regardless of ScopeField.
//
// Algorithm: build a control→chains inverted index once, walk
// failures exactly once, route each failure into per-chain
// per-scope buckets. The earlier shape iterated chains and scanned
// the full failure slice per chain — O(chains × failures). The
// inverted-index form is O(Σ |chain.ControlIDs|) for the index
// build plus O(failures × avg_chains_per_control) for the walk —
// roughly fan-out 1-3 chains per control, so essentially O(failures)
// in practice. The terminal sort guarantees the original
// determinism contract regardless of the new map-iteration order.
func DetectChains(
	failures []FailingControl,
	chains []policy.ChainDefinition,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
	scopeResolver ScopeResolver,
) []findingsdata.CompoundFinding {
	// Build the inverted index once.
	controlToChains := make(map[kernel.ControlID][]int, len(chains))
	for i := range chains {
		for _, cid := range chains[i].ControlIDs {
			controlToChains[cid] = append(controlToChains[cid], i)
		}
	}

	// Walk failures once. Allocate per-chain buckets lazily so
	// chains with zero matching failures pay nothing.
	buckets := make([]*chainBuckets, len(chains))
	for j := range failures {
		f := &failures[j]
		chainIdxs := controlToChains[f.ControlID]
		if len(chainIdxs) == 0 {
			continue
		}
		for _, ci := range chainIdxs {
			chain := &chains[ci]
			scope, resolved := groupingKey(chain, f.AssetID, scopeResolver)
			if scope == "" {
				continue // not evaluable (e.g. account-scoped chain, no account_id)
			}
			b := buckets[ci]
			if b == nil {
				b = &chainBuckets{
					byScope:         make(map[string]map[kernel.ControlID]struct{}),
					assetsByScope:   make(map[string]map[asset.ID]struct{}),
					resolvedByScope: make(map[string]struct{}),
				}
				buckets[ci] = b
			}
			if b.byScope[scope] == nil {
				b.byScope[scope] = make(map[kernel.ControlID]struct{})
				b.assetsByScope[scope] = make(map[asset.ID]struct{})
			}
			b.byScope[scope][f.ControlID] = struct{}{}
			b.assetsByScope[scope][f.AssetID] = struct{}{}
			if resolved {
				b.resolvedByScope[scope] = struct{}{}
			}
		}
	}

	// Emit findings: iterate chains in catalog order (so iteration
	// order is stable for the few cases where the terminal sort is
	// a no-op — single chain, single scope), skipping chains with
	// no buckets.
	var findings []findingsdata.CompoundFinding
	for i := range chains {
		b := buckets[i]
		if b == nil {
			continue
		}
		chain := &chains[i]
		for scope, scopeFailing := range b.byScope {
			if finding, ok := emitChainFinding(chain, scope, scopeFailing, b, controlLookup); ok {
				findings = append(findings, finding)
			}
		}
	}

	// Sort by (chain id, scope id, asset id) so the output is deterministic
	// across runs. Both the inner failure walk above and the bucket
	// emission iterate maps with randomised order, so the sort is the
	// foundational source of determinism for chain_findings output.
	slices.SortFunc(findings, func(a, b findingsdata.CompoundFinding) int {
		if c := cmp.Compare(string(a.ChainID), string(b.ChainID)); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ScopeID, b.ScopeID); c != 0 {
			return c
		}
		return cmp.Compare(string(a.AssetID), string(b.AssetID))
	})

	return findings
}

// emitChainFinding turns one (chain, scope, bucket) into a
// CompoundFinding when the failing-control count meets the chain's
// escalation threshold. Returns (zero, false) when the threshold
// is not met so the caller can skip silently.
//
// Extracted from the body of DetectChains so the new index-driven
// loop reads as data-flow (build index, walk failures, emit), with
// the per-bucket bookkeeping isolated here.
func emitChainFinding(
	chain *policy.ChainDefinition,
	scope string,
	scopeFailing map[kernel.ControlID]struct{},
	b *chainBuckets,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
) (findingsdata.CompoundFinding, bool) {
	var failing []kernel.ControlID
	var holding []kernel.ControlID
	for _, cid := range chain.ControlIDs {
		if _, ok := scopeFailing[cid]; ok {
			failing = append(failing, cid)
		} else {
			holding = append(holding, cid)
		}
	}

	if len(failing) < chain.EscalationThreshold {
		return findingsdata.CompoundFinding{}, false
	}

	// Collect attack stages and compute scope-aware blast multiplier.
	stageSet := make(map[kernel.AttackStage]struct{})
	maxBlast := 1.0
	for _, cid := range failing {
		if ctl, ok := controlLookup[cid]; ok {
			if stage := ctl.AttackStage(); stage != "" {
				stageSet[stage] = struct{}{}
			}
			mult := scopeAdjustedBlast(ctl)
			if mult > maxBlast {
				maxBlast = mult
			}
		}
	}

	stages := make([]kernel.AttackStage, 0, len(stageSet))
	for s := range stageSet {
		stages = append(stages, s)
	}
	slices.SortFunc(stages, func(a, b kernel.AttackStage) int {
		return cmp.Compare(string(a), string(b))
	})

	escalation := ChainEscalation(len(failing))
	base := baseScoreFromMembers(failing, controlLookup)
	score := Compound(base, escalation, maxBlast)
	if score > float64(ScoreCatastrophic) {
		score = float64(ScoreCatastrophic)
	}

	narrative := buildNarrative(chain, failing)
	contributing := sortedAssetIDs(b.assetsByScope[scope])

	representativeAsset := contributing[0] // deterministic via sort
	finding := findingsdata.CompoundFinding{
		FindingID:         findingsdata.StableChainFindingID(chain.ID, representativeAsset, scope),
		ChainID:           chain.ID,
		AssetID:           representativeAsset,
		Description:       chain.Description,
		ControlsFailing:   failing,
		MissingSafeguards: holding,
		CompoundScore:     score,
		Severity:          chain.CompoundSeverity,
		Narrative:         narrative,
		AttackStages:      stages,
	}
	// ContributingAssets and ScopeID/ScopeField surface only on
	// scope-grouped chains. For legacy asset.ID-grouped chains every
	// contributing asset.ID equals AssetID, so the slice would
	// duplicate AssetID — and adding it unconditionally would churn
	// every chain golden in the repo. Emit only when scope_field
	// actually drove grouping.
	_, isResolved := b.resolvedByScope[scope]
	if isResolved && (chain.ScopeField != "" || chain.Scope.IsGlobal() || chain.Scope.IsAccount()) {
		finding.ScopeID = scope
		finding.ScopeField = chain.ScopeField
		finding.ContributingAssets = contributing
	}
	return finding, true
}

// groupingKey returns the scope value to use when bucketing one failing
// control under a chain, plus a flag indicating whether the value came
// from the resolver (true) or from the asset.ID fallback (false). When
// the chain declares ScopeField and the resolver returns a non-empty
// value, that value is the key and resolved=true; otherwise the
// asset.ID is used and resolved=false. The asset.ID fallback also
// applies when the resolver is nil — defensive for tests and any caller
// that has no asset properties at hand.
//
// scope: account returns ("", false) when the asset has no account_id —
// a not-evaluable signal. Callers must skip entries where key is "".
func groupingKey(chain *policy.ChainDefinition, assetID asset.ID, resolver ScopeResolver) (string, bool) {
	if chain.Scope.IsGlobal() {
		return "__global__", true
	}
	if chain.Scope.IsAccount() {
		if resolver == nil {
			return "", false
		}
		if v, ok := resolver(assetID, "account_id"); ok && v != "" {
			return v, true
		}
		return "", false
	}
	if chain.ScopeField == "" || resolver == nil {
		return string(assetID), false
	}
	if v, ok := resolver(assetID, chain.ScopeField); ok && v != "" {
		return v, true
	}
	return string(assetID), false
}

// sortedAssetIDs returns the keys of the set in lexical order so chain
// findings are deterministic across runs.
func sortedAssetIDs(set map[asset.ID]struct{}) []asset.ID {
	out := make([]asset.ID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b asset.ID) int {
		return cmp.Compare(string(a), string(b))
	})
	return out
}

// baseScoreFromMembers derives the chain base score from the highest
// severity among its failing member controls.
func baseScoreFromMembers(
	failing []kernel.ControlID,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
) float64 {
	maxSev := policy.SeverityLow
	for _, cid := range failing {
		if ctl, ok := controlLookup[cid]; ok {
			if ctl.Severity > maxSev {
				maxSev = ctl.Severity
			}
		}
	}
	switch maxSev {
	case policy.SeverityCritical:
		return float64(ScoreCritical) // 90
	case policy.SeverityHigh:
		return 75
	case policy.SeverityMedium:
		return 50
	default:
		return float64(ScoreInfo)
	}
}

// scopeAdjustedBlast computes the effective blast multiplier based on
// the control's declared scope. Account-scoped controls (CloudTrail)
// apply their full multiplier because they blind the entire account.
// Network-scoped controls (VPC Flow Logs) are attenuated because the
// chain may span resources outside that network. Resource-scoped
// controls (S3 logging) are further attenuated because the detection
// gap is local to one resource.
//
// This prevents a single disabled S3 access log from inflating scores
// across unrelated resources — the multiplier is proportional to the
// blast radius scope.
//
// Attenuation model rationale:
//
//	account (1.00x): No attenuation — account-scoped controls affect
//	  every resource. A disabled CloudTrail blinds the entire account.
//
//	network (0.75x of excess): Network access controls (VPC, SGs, NACLs)
//	  provide a partial barrier. A misconfigured resource behind a
//	  network control is 75% as impactful because the network layer
//	  adds friction for an attacker.
//
//	resource (0.50x of excess): A resource-level control (bucket policy,
//	  KMS key policy) provides a stronger barrier than network controls.
//	  Misconfiguration requires both a network path AND a resource
//	  policy bypass — 50% as impactful as direct exposure.
//
// These values are intentional defaults derived from defense-in-depth
// layering. Organizations with different network posture assumptions
// can override blast multipliers per control definition.
func scopeAdjustedBlast(ctl *policy.ControlDefinition) float64 {
	mult := ctl.BlastMultiplier()
	if mult <= 1.0 {
		return 1.0
	}

	scope := ctl.BlastScope()
	switch scope {
	case kernel.BlastScopeAccount:
		return mult // Full multiplier — blinds everything
	case kernel.BlastScopeNetwork:
		// Attenuate: network scope may not cover all chain resources.
		// Apply 75% of the excess above 1.0.
		return 1.0 + (mult-1.0)*0.75
	case kernel.BlastScopeResource:
		// Attenuate further: local detection gap.
		// Apply 50% of the excess above 1.0.
		return 1.0 + (mult-1.0)*0.50
	default:
		return mult
	}
}

// DetectNearMisses finds chains that are exactly one control short of
// firing. Uses the same bucket-building algorithm as DetectChains.
func DetectNearMisses(
	failures []FailingControl,
	chains []policy.ChainDefinition,
	scopeResolver ScopeResolver,
) []findingsdata.NearMissChain {
	controlToChains := make(map[kernel.ControlID][]int, len(chains))
	for i := range chains {
		for _, cid := range chains[i].ControlIDs {
			controlToChains[cid] = append(controlToChains[cid], i)
		}
	}

	buckets := make([]*chainBuckets, len(chains))
	for j := range failures {
		f := &failures[j]
		for _, ci := range controlToChains[f.ControlID] {
			chain := &chains[ci]
			scope, resolved := groupingKey(chain, f.AssetID, scopeResolver)
			if scope == "" {
				continue // not evaluable (e.g. account-scoped chain, no account_id)
			}
			b := buckets[ci]
			if b == nil {
				b = &chainBuckets{
					byScope:         make(map[string]map[kernel.ControlID]struct{}),
					assetsByScope:   make(map[string]map[asset.ID]struct{}),
					resolvedByScope: make(map[string]struct{}),
				}
				buckets[ci] = b
			}
			if b.byScope[scope] == nil {
				b.byScope[scope] = make(map[kernel.ControlID]struct{})
				b.assetsByScope[scope] = make(map[asset.ID]struct{})
			}
			b.byScope[scope][f.ControlID] = struct{}{}
			b.assetsByScope[scope][f.AssetID] = struct{}{}
			if resolved {
				b.resolvedByScope[scope] = struct{}{}
			}
		}
	}

	var nearMisses []findingsdata.NearMissChain
	for i := range chains {
		b := buckets[i]
		if b == nil {
			continue
		}
		chain := &chains[i]
		// Threshold-1 chains have no one-away state: they're either
		// safe (0 failing) or exploitable (1 failing). The near-miss
		// condition (len(failing) == threshold-1 AND len(failing) > 0)
		// is contradictory for threshold=1.
		if chain.EscalationThreshold <= 1 {
			continue
		}
		for scope, scopeFailing := range b.byScope {
			var failing, holding []kernel.ControlID
			for _, cid := range chain.ControlIDs {
				if _, ok := scopeFailing[cid]; ok {
					failing = append(failing, cid)
				} else {
					holding = append(holding, cid)
				}
			}
			// Near miss: exactly one control short of threshold.
			if len(failing) == chain.EscalationThreshold-1 && len(failing) > 0 {
				for _, missing := range holding {
					nearMisses = append(nearMisses, findingsdata.NearMissChain{
						ChainID:         chain.ID,
						Description:     chain.Description,
						ControlsFailing: failing,
						MissingControl:  missing,
						Severity:        chain.CompoundSeverity,
						ScopeID:         scope,
					})
				}
			}
		}
	}

	slices.SortFunc(nearMisses, func(a, b findingsdata.NearMissChain) int {
		if c := cmp.Compare(string(a.ChainID), string(b.ChainID)); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ScopeID, b.ScopeID); c != 0 {
			return c
		}
		return cmp.Compare(string(a.MissingControl), string(b.MissingControl))
	})
	return nearMisses
}

func buildNarrative(chain *policy.ChainDefinition, failing []kernel.ControlID) string {
	ids := make([]string, len(failing))
	for i, id := range failing {
		ids[i] = string(id)
	}
	return chain.Description + " Failing: " + strings.Join(ids, ", ") + "."
}

// AnnotateDependencies post-processes DetectChains output: for each
// finding whose chain declares implicit_dependencies, resolve each
// dependency via the supplied resolver and attach diagnostics. When
// resolver is nil, all dependencies resolve as RanOK (backward-
// compatible no-op).
func AnnotateDependencies(
	findings []findingsdata.CompoundFinding,
	chains []policy.ChainDefinition,
	resolver policy.DependencyResolver,
) []findingsdata.CompoundFinding {
	if resolver == nil || len(findings) == 0 {
		return findings
	}

	chainByID := make(map[kernel.ChainID]*policy.ChainDefinition, len(chains))
	for i := range chains {
		chainByID[chains[i].ID] = &chains[i]
	}

	for i := range findings {
		f := &findings[i]
		chain := chainByID[f.ChainID]
		if chain == nil || len(chain.ImplicitDependencies) == 0 {
			continue
		}
		for _, dep := range chain.ImplicitDependencies {
			status := resolver.Status(dep.Source)
			switch dep.Fallback {
			case policy.FallbackFailClosed:
				if status == policy.DependencyNotRun || status == policy.DependencyRanEmpty || status == policy.DependencyUnknown {
					if dep.Diagnostic != "" {
						f.DependencyDiagnostics = append(f.DependencyDiagnostics, dep.Diagnostic)
					}
				}
			case policy.FallbackCrossValidate:
				if status != policy.DependencyRanOK && dep.Diagnostic != "" {
					f.DependencyDiagnostics = append(f.DependencyDiagnostics, dep.Diagnostic)
				}
			case policy.FallbackFailOpen:
				// Intentional: no annotation.
			}
		}
	}
	return findings
}
