package engine

import (
	"log/slog"
	"slices"
	"sync"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// stripeCount is the shard count for the collector's per-asset
// state. The Phase 2 mutex profile
// (docs/perf/mutex-profile-2026-05-27.md) showed 99.74% of all
// blocking delay sitting on a single mutex serialising every
// per-asset write. Striping by asset.ID lets goroutines for
// different assets proceed independently. 16 is the conventional
// choice: large enough to decouple typical contention on an
// 8-core box, small enough that the stripe array fits in a few
// cache lines.
//
// Must be a power of two so the modulo is a cheap bitmask.
const (
	stripeCount = 16
	stripeMask  = stripeCount - 1
)

// stripeIndex maps an asset.ID to a stripe via inline FNV-1a hash.
// Inline rather than `hash/fnv.New32a()` because the latter
// allocates a hasher per call, which is exactly what the hot path
// cannot afford. FNV-1a is the right cost/distribution trade-off
// for short strings like asset IDs.
func stripeIndex(id asset.ID) int {
	const (
		offset32 uint32 = 2166136261
		prime32  uint32 = 16777619
	)
	h := offset32
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= prime32
	}
	return int(h & stripeMask)
}

// assetRegistry provides an internal set for tracking unique cloud assets.
type assetRegistry map[asset.ID]struct{}

// register inserts an asset ID and returns true if it is a new discovery.
func (s assetRegistry) register(id asset.ID) bool {
	if _, ok := s[id]; ok {
		return false
	}
	s[id] = struct{}{}
	return true
}

// collectorStripe is one shard of the per-asset collector state.
// Every field is guarded by mu — goroutines operating on a
// different stripe never touch this one's lock. The fields are
// the same set the unstriped collector used (findings, checks,
// exemptedAssets, three asset registries); they are split across
// stripes by asset.ID hash, then merged in Snapshot.
type collectorStripe struct {
	mu                 sync.Mutex
	findings           []evaluation.Finding
	checks             []evaluation.ResourceCheck
	exemptedAssets     []asset.ExemptedAsset
	seenAssets         assetRegistry
	nonCompliantAssets assetRegistry
	exemptAssets       assetRegistry
}

// AssessmentCollector gathers security findings, resource checks, and
// compliance metadata across multiple evaluation cycles.
// All methods are safe for concurrent use.
//
// The per-asset state (findings, checks, exemptedAssets, asset
// registries) lives on N stripes keyed by asset.ID hash. The
// non-asset-keyed state has its own narrow mutexes:
//   - skippedControls is recorded sequentially from Assess (not
//     from the applyControl goroutine pool), so contention is
//     non-existent; a flat mutex suffices.
//   - findingIDs is the cross-asset dedup set. A single FindingID
//     can be produced by multiple (control, asset) pairs
//     (recurrence strategy across snapshots, identity matchers
//     across iterations), so the dedup decision must span
//     stripes. sync.Map.LoadOrStore is the atomic
//     check-and-claim primitive that matches.
type AssessmentCollector struct {
	stripes [stripeCount]*collectorStripe

	skippedMu       sync.Mutex
	skippedControls []evaluation.SkippedControl

	// findingIDs deduplicates batches across multiple
	// RecordFindings calls. sync.Map.LoadOrStore gives an atomic
	// "claim this id, tell me if I won" primitive — exactly the
	// dedup semantics RecordFindings needs without taking a
	// blocking mutex for every finding. The dedup set spans
	// stripes by design (see the type doc above).
	findingIDs sync.Map
}

// NewCollector initializes the assessment collector.
// assetHint allows for pre-allocation of tracking registries based on observation size.
func NewCollector(assetHint int) *AssessmentCollector {
	c := &AssessmentCollector{}
	// Divide the asset hint across stripes so the per-stripe
	// registries pre-allocate in proportion. Round up to keep
	// the per-stripe hint usefully non-zero for small hints.
	perStripe := (assetHint + stripeCount - 1) / stripeCount
	for i := range c.stripes {
		c.stripes[i] = &collectorStripe{
			seenAssets:         make(assetRegistry, perStripe),
			nonCompliantAssets: make(assetRegistry, perStripe),
			exemptAssets:       make(assetRegistry, perStripe),
		}
	}
	return c
}

// stripeFor returns the stripe holding state for the given asset.
func (c *AssessmentCollector) stripeFor(id asset.ID) *collectorStripe {
	return c.stripes[stripeIndex(id)]
}

// RecordExemption marks an asset as exempt from policy enforcement.
// It returns true if this is the first time the asset has been exempted in the session.
func (c *AssessmentCollector) RecordExemption(id asset.ID) bool {
	s := c.stripeFor(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exemptAssets.register(id)
}

// RecordSkippedControl logs a security control that was bypassed during the run.
//
// Called from Assess's sequential setup loop (before the per-control
// goroutine pool starts) for non-evaluatable controls, so the lock is
// uncontended in practice. The mutex is here for the rare future
// caller that might invoke it from a goroutine — correct by
// construction, cheap in steady state.
func (c *AssessmentCollector) RecordSkippedControl(id kernel.ControlID, name, reason string) {
	c.skippedMu.Lock()
	defer c.skippedMu.Unlock()
	c.skippedControls = append(c.skippedControls, evaluation.SkippedControl{
		ControlID:   id,
		ControlName: name,
		Reason:      reason,
	})
}

// RecordExemptedAsset appends the detail of an exempted asset to the final report.
func (c *AssessmentCollector) RecordExemptedAsset(id asset.ID, pattern, reason string) {
	s := c.stripeFor(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exemptedAssets = append(s.exemptedAssets, asset.ExemptedAsset{
		ID:      id,
		Pattern: pattern,
		Reason:  reason,
	})
}

// RecordCheck appends a granular resource evaluation result.
//
// A zero ControlID signals an upstream skip from a strategy that
// received a nil control (the unsafeStateStrategy /
// unsafeDurationStrategy nil guard returns the zero ResourceCheck).
// Drop those entries rather than letting them pollute the report —
// a "" control_id row is meaningless evidence and breaks downstream
// rollups that key on control identity.
func (c *AssessmentCollector) RecordCheck(check evaluation.ResourceCheck) {
	if check.ControlID == "" {
		return
	}
	s := c.stripeFor(check.AssetID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks = append(s.checks, check)
}

// RecordFindings appends a batch of identified security violations.
// Findings sharing a FindingID with an already-recorded entry are
// dropped: strategies that fire on overlapping inputs (recurrence
// over multiple snapshots, identity matchers across iterations) used
// to double-count and inflate the violations summary. Duplicates
// are logged so the source of the duplication is visible without
// having to inspect every strategy by hand.
//
// Dedup happens via sync.Map.LoadOrStore — atomic "claim this id,
// tell me if I won" — before the finding is appended to the
// asset's stripe. This separates the cross-asset dedup decision
// from the per-asset append, so concurrent goroutines for
// different assets don't contend on the same lock.
func (c *AssessmentCollector) RecordFindings(findings []*evaluation.Finding) {
	for _, f := range findings {
		if f == nil {
			continue
		}
		// Mirror RecordCheck's behavior: a finding with no
		// attribution is meaningless evidence and would cause
		// FallbackID-based identity collisions, coalescing distinct
		// rows into one. Drop instead so the report stays clean.
		if f.IsUnattributed() {
			slog.Warn("collector: finding is unattributed; skipping",
				"finding_id", f.FindingID, "asset_id", f.AssetID)
			continue
		}
		fid := f.FindingID
		if fid == "" {
			// Synthesise a deterministic fallback ID from the
			// (control, asset) pair so the finding still
			// participates in dedup. The earlier shape warned and
			// then appended, so a strategy that forgot to assign a
			// FindingID could produce N copies of the same finding
			// — silent duplicate output. The fallback gives every
			// such finding an ID that collides on repeat
			// (control,asset) pairs, restoring the dedup contract.
			fallback := kernel.FindingID(f.FallbackID())
			slog.Warn("collector: finding has empty FindingID; using fallback for dedup",
				"control_id", f.ControlID, "asset_id", f.AssetID,
				"fallback_finding_id", fallback)
			fid = fallback
		}
		// LoadOrStore returns (existing, true) if the key was
		// already present. We want the inverse: append iff the
		// key was NOT present (we claimed it). The cross-asset
		// dedup happens here, atomically, without taking any
		// stripe lock.
		if _, dup := c.findingIDs.LoadOrStore(fid, struct{}{}); dup {
			slog.Warn("collector: duplicate finding suppressed",
				"finding_id", fid, "control_id", f.ControlID)
			continue
		}
		s := c.stripeFor(f.AssetID)
		s.mu.Lock()
		s.findings = append(s.findings, *f)
		s.mu.Unlock()
	}
}

// RecordSeenAsset registers id in the seen-assets set under the
// collector mutex. Returns true if the asset is new in this run.
func (c *AssessmentCollector) RecordSeenAsset(id asset.ID) bool {
	s := c.stripeFor(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seenAssets.register(id)
}

// RecordNonCompliantAsset registers id in the non-compliant set under
// the collector mutex. Returns true if the asset is new in this run.
func (c *AssessmentCollector) RecordNonCompliantAsset(id asset.ID) bool {
	s := c.stripeFor(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonCompliantAssets.register(id)
}

// SeenAssetCount returns the number of unique assets seen so far.
// Sums across all stripes — every asset.ID hashes to exactly one
// stripe, so the per-stripe count is non-overlapping and the sum
// is the true total.
func (c *AssessmentCollector) SeenAssetCount() int {
	var total int
	for i := range c.stripes {
		s := c.stripes[i]
		s.mu.Lock()
		total += len(s.seenAssets)
		s.mu.Unlock()
	}
	return total
}

// NonCompliantAssetCount returns the number of unique non-compliant
// assets seen so far. See SeenAssetCount for the cross-stripe sum
// note.
func (c *AssessmentCollector) NonCompliantAssetCount() int {
	var total int
	for i := range c.stripes {
		s := c.stripes[i]
		s.mu.Lock()
		total += len(s.nonCompliantAssets)
		s.mu.Unlock()
	}
	return total
}

// CollectorSnapshot is the read-only view compileReport needs.
// All fields are slices owned by the receiver — the caller must
// not mutate them in place. Snapshot returns deep-cloned slices
// (see Snapshot doc) so in-place sorts / mutations downstream do
// not poison the collector's authoritative state.
type CollectorSnapshot struct {
	Findings        []evaluation.Finding
	Checks          []evaluation.ResourceCheck
	SkippedControls []evaluation.SkippedControl
	ExemptedAssets  []asset.ExemptedAsset
}

// Snapshot captures a consistent view of the collector by locking
// each stripe in turn, copying its slices out, then releasing.
//
// This is called by compileReport AFTER Assess() returns — no
// concurrent writers are active at the call point. The
// per-stripe locks are taken defensively in case a future caller
// invokes Snapshot mid-run; even then, the per-stripe locks
// serialise individual writers without serialising the whole
// collector.
//
// Determinism note: the merge order across stripes is
// FNV-hash-determined and therefore stable for a given input,
// but the downstream compileReport pass always sorts Findings,
// Checks, and ExemptedAssets before emitting the report. The
// stripe-merge order does not reach the caller.
//
// Cloning every slice is necessary because compileReport sorts
// Findings / Checks / ExemptedAssets in place; without the
// clone, the in-place sort would corrupt the collector's
// authoritative storage. Findings additionally deep-clone their
// Evidence.Misconfigurations and Evidence.RootCauses slices for
// the same reason.
func (c *AssessmentCollector) Snapshot() CollectorSnapshot {
	var (
		findings []evaluation.Finding
		checks   []evaluation.ResourceCheck
		exempted []asset.ExemptedAsset
	)
	// Pre-size the destination slices by summing per-stripe lengths
	// in a first locked pass, then copy in a second. Each stripe is
	// locked only briefly twice rather than held through a growing
	// append. For typical assessment sizes (thousands of findings)
	// the saving is small but it keeps Snapshot from being a worst-
	// case allocation pattern.
	var totalFindings, totalChecks, totalExempted int
	for i := range c.stripes {
		s := c.stripes[i]
		s.mu.Lock()
		totalFindings += len(s.findings)
		totalChecks += len(s.checks)
		totalExempted += len(s.exemptedAssets)
		s.mu.Unlock()
	}
	findings = make([]evaluation.Finding, 0, totalFindings)
	checks = make([]evaluation.ResourceCheck, 0, totalChecks)
	exempted = make([]asset.ExemptedAsset, 0, totalExempted)
	for i := range c.stripes {
		s := c.stripes[i]
		s.mu.Lock()
		findings = append(findings, s.findings...)
		checks = append(checks, s.checks...)
		exempted = append(exempted, s.exemptedAssets...)
		s.mu.Unlock()
	}
	// Deep-clone evidence slices so downstream in-place sorts and
	// mutations don't poison the collector's backing storage. The
	// top-level slices.Clone equivalent above (cap-sized append)
	// already copied the Finding struct values; this loop copies
	// the slices nested inside each Finding.Evidence.
	for i := range findings {
		findings[i].Evidence.Misconfigurations = slices.Clone(findings[i].Evidence.Misconfigurations)
		findings[i].Evidence.RootCauses = slices.Clone(findings[i].Evidence.RootCauses)
	}

	c.skippedMu.Lock()
	skipped := slices.Clone(c.skippedControls)
	c.skippedMu.Unlock()

	return CollectorSnapshot{
		Findings:        findings,
		Checks:          checks,
		SkippedControls: skipped,
		ExemptedAssets:  exempted,
	}
}
