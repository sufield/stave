package engine

import (
	"log/slog"
	"slices"
	"sync"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

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

// AssessmentCollector gathers security findings, resource checks, and
// compliance metadata across multiple evaluation cycles.
// All methods are safe for concurrent use.
type AssessmentCollector struct {
	mu              sync.Mutex
	findings        []evaluation.Finding
	checks          []evaluation.ResourceCheck
	skippedControls []evaluation.SkippedControl
	exemptedAssets  []asset.ExemptedAsset

	seenAssets         assetRegistry
	nonCompliantAssets assetRegistry
	exemptAssets       assetRegistry
	// findingIDs deduplicates batches across multiple
	// RecordFindings calls. Strategies that emit overlapping
	// findings (e.g. a recurrence strategy that re-fires for the
	// same control on the same asset across snapshots) used to
	// double-count, inflating the violations summary and producing
	// duplicate report rows.
	findingIDs map[kernel.FindingID]struct{}
}

// NewCollector initializes the assessment collector.
// assetHint allows for pre-allocation of tracking registries based on observation size.
func NewCollector(assetHint int) *AssessmentCollector {
	return &AssessmentCollector{
		seenAssets:         make(assetRegistry, assetHint),
		nonCompliantAssets: make(assetRegistry, assetHint),
		exemptAssets:       make(assetRegistry, assetHint),
		findingIDs:         make(map[kernel.FindingID]struct{}, assetHint),
	}
}

// RecordExemption marks an asset as exempt from policy enforcement.
// It returns true if this is the first time the asset has been exempted in the session.
func (c *AssessmentCollector) RecordExemption(id asset.ID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exemptAssets.register(id)
}

// RecordSkippedControl logs a security control that was bypassed during the run.
func (c *AssessmentCollector) RecordSkippedControl(id kernel.ControlID, name, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.skippedControls = append(c.skippedControls, evaluation.SkippedControl{
		ControlID:   id,
		ControlName: name,
		Reason:      reason,
	})
}

// RecordExemptedAsset appends the detail of an exempted asset to the final report.
func (c *AssessmentCollector) RecordExemptedAsset(id asset.ID, pattern, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exemptedAssets = append(c.exemptedAssets, asset.ExemptedAsset{
		ID:      id,
		Pattern: pattern,
		Reason:  reason,
	})
}

// RecordCheck appends a granular resource evaluation result.
func (c *AssessmentCollector) RecordCheck(check evaluation.ResourceCheck) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks = append(c.checks, check)
}

// RecordFindings appends a batch of identified security violations.
// Findings sharing a FindingID with an already-recorded entry are
// dropped: strategies that fire on overlapping inputs (recurrence
// over multiple snapshots, identity matchers across iterations) used
// to double-count and inflate the violations summary. Duplicates
// are logged so the source of the duplication is visible without
// having to inspect every strategy by hand.
func (c *AssessmentCollector) RecordFindings(findings []*evaluation.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range findings {
		if f == nil {
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
			fallback := kernel.FindingID(string(f.ControlID) + "/" + string(f.AssetID))
			slog.Warn("collector: finding has empty FindingID; using fallback for dedup",
				"control_id", f.ControlID, "asset_id", f.AssetID,
				"fallback_finding_id", fallback)
			fid = fallback
		}
		if _, dup := c.findingIDs[fid]; dup {
			slog.Warn("collector: duplicate finding suppressed",
				"finding_id", fid, "control_id", f.ControlID)
			continue
		}
		c.findingIDs[fid] = struct{}{}
		c.findings = append(c.findings, *f)
	}
}

// RecordSeenAsset registers id in the seen-assets set under the
// collector mutex. Returns true if the asset is new in this run.
func (c *AssessmentCollector) RecordSeenAsset(id asset.ID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seenAssets.register(id)
}

// RecordNonCompliantAsset registers id in the non-compliant set under
// the collector mutex. Returns true if the asset is new in this run.
func (c *AssessmentCollector) RecordNonCompliantAsset(id asset.ID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nonCompliantAssets.register(id)
}

// SeenAssetCount returns the number of unique assets seen so far.
// Read under the collector mutex so callers can reach for the value
// after concurrent applyControl calls have returned.
func (c *AssessmentCollector) SeenAssetCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seenAssets)
}

// NonCompliantAssetCount returns the number of unique non-compliant
// assets seen so far. See SeenAssetCount for locking notes.
func (c *AssessmentCollector) NonCompliantAssetCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.nonCompliantAssets)
}

// CollectorSnapshot is the read-only view compileReport needs.
// All fields are slices owned by the receiver — the caller must
// not mutate them in place. Returned slices share the underlying
// backing array with the collector; if a caller needs to mutate
// (e.g. sort), they should re-slice or clone first.
type CollectorSnapshot struct {
	Findings        []evaluation.Finding
	Checks          []evaluation.ResourceCheck
	SkippedControls []evaluation.SkippedControl
	ExemptedAssets  []asset.ExemptedAsset
}

// Snapshot captures the slice headers under the mutex so a single
// compileReport call sees a consistent view of the collector. The
// earlier shape read s.collector.findings / .checks / .exemptedAssets
// directly without locking; the writers (RecordFindings,
// RecordCheck, etc.) acquire the mutex, but compileReport's
// unsynchronised reads were a race even when serialised by the
// session's applyControlInUse atomic — Go's memory model treats
// the unsynchronised slice-header read as undefined behaviour.
func (c *AssessmentCollector) Snapshot() CollectorSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Clone every slice. The earlier shape returned shared slice
	// headers; compileReport then in-place sorted Findings / Checks
	// / ExemptedAssets, which mutated the collector's underlying
	// arrays under the lock-protected writes' nose. Cloning at
	// the read boundary turns Snapshot into a true snapshot —
	// callers can sort, filter, or otherwise mutate the returned
	// slices without poisoning the collector for any subsequent
	// run that reuses the same instance.
	return CollectorSnapshot{
		Findings:        slices.Clone(c.findings),
		Checks:          slices.Clone(c.checks),
		SkippedControls: slices.Clone(c.skippedControls),
		ExemptedAssets:  slices.Clone(c.exemptedAssets),
	}
}
