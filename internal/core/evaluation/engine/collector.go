package engine

import (
	"log/slog"
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
		fid := kernel.FindingID(f.FindingID)
		if fid != "" {
			if _, dup := c.findingIDs[fid]; dup {
				slog.Warn("collector: duplicate finding suppressed",
					"finding_id", fid, "control_id", f.ControlID)
				continue
			}
			c.findingIDs[fid] = struct{}{}
		}
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
